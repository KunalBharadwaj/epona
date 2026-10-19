#pragma once
//
// One TCP connection = one Transmission Control Block (TCB) running the RFC 793
// state machine, with the pieces that make it behave under loss and congestion:
//
//   * a SEND BUFFER holding unacknowledged bytes, so we can retransmit;
//   * a RETRANSMISSION timer with an RTO from the Jacobson/Karels estimator
//     (smoothed RTT + variance), exponential backoff, and Karn's algorithm;
//   * FLOW CONTROL: never send past the peer's advertised receive window;
//   * CONGESTION CONTROL (TCP Reno): slow start, AIMD congestion avoidance,
//     and fast retransmit / fast recovery on three duplicate ACKs;
//   * RECEIVE REASSEMBLY: buffer out-of-order segments so a single loss costs
//     one retransmit, not a whole window.
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <vector>

#include "ip/ipv4_address.hpp"
#include "net/event_loop.hpp"
#include "tcp/send_ring.hpp"
#include "tcp/tcp_header.hpp"

namespace tcp {

class Tcp; // owner; defined in tcp.hpp

enum class State {
    SynSent, SynReceived, Established,
    FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, Closed,
};

const char* to_string(State s) noexcept;

struct FourTuple {
    ip::Ipv4Addr  local_ip;
    ip::Ipv4Addr  remote_ip;
    std::uint16_t local_port  = 0;
    std::uint16_t remote_port = 0;
    bool operator==(const FourTuple&) const = default;
};

struct FourTupleHash {
    std::size_t operator()(const FourTuple& t) const noexcept {
        std::uint64_t h = (static_cast<std::uint64_t>(t.local_ip.value) << 32) ^
                          t.remote_ip.value;
        h ^= (static_cast<std::uint64_t>(t.local_port) << 16) ^ t.remote_port;
        h *= 0x9E3779B97F4A7C15ull;
        return static_cast<std::size_t>(h ^ (h >> 32));
    }
};

class TcpConnection {
public:
    using DataCallback  = std::function<void(TcpConnection&, std::span<const std::byte>)>;
    using EventCallback = std::function<void(TcpConnection&)>;

    DataCallback  on_data;
    EventCallback on_close;
    EventCallback on_open;

    TcpConnection(Tcp& owner, FourTuple tuple);
    ~TcpConnection();

    // ----- app API -----
    void send(std::span<const std::byte> data); // queue application bytes
    void close();                               // orderly shutdown

    // ----- manager hooks -----
    void passive_open(const TcpHeader& syn);
    void active_open();
    void on_segment(const TcpHeader& h, std::span<const std::byte> data);

    // ----- introspection / stats -----
    State            state() const noexcept { return state_; }
    const FourTuple& tuple() const noexcept { return tuple_; }
    bool             finished() const noexcept { return finished_; }
    std::uint32_t    snd_nxt() const noexcept { return snd_nxt_; }
    std::uint32_t    rcv_nxt() const noexcept { return rcv_nxt_; }
    std::uint32_t    cwnd() const noexcept { return cwnd_; }
    std::uint32_t    ssthresh() const noexcept { return ssthresh_; }
    double           rto_ms() const noexcept { return rto_ms_; }
    double           srtt_ms() const noexcept { return srtt_ms_; }
    std::uint64_t    retransmits() const noexcept { return retransmits_; }
    std::uint64_t    fast_retransmits() const noexcept { return fast_retransmits_; }

private:
    // --- transmission ---
    void send_raw(std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                  std::span<const std::byte> payload = {}, bool with_mss = false);
    void send_ack();
    void send_rst();
    void try_send();                 // push queued data within the windows
    void send_fin_if_ready();        // emit FIN once all data is out
    void retransmit_oldest();        // resend from snd_una
    std::uint16_t advertised_window() const; // our current receive window

    // --- inbound processing ---
    void handle_syn_sent(const TcpHeader& h, std::span<const std::byte> data);
    void process_ack(const TcpHeader& h, std::size_t data_len);
    void deliver_in_order(std::uint32_t seq, std::span<const std::byte> data);
    void handle_fin();

    // --- RTT / RTO ---
    void update_rtt(double sample_ms);
    void arm_rto();
    void disarm_rto();
    void on_rto();

    // --- zero-window persist ---
    void arm_persist();
    void disarm_persist();
    void on_persist();

    // --- congestion control ---
    void on_new_ack(std::uint32_t acked_bytes);
    void enter_loss_recovery(bool fast); // set ssthresh/cwnd on loss

    // --- SACK (RFC 2018) ---
    std::uint8_t build_sack_blocks(std::array<SackBlock, 3>& out) const; // receiver side
    void         record_sack(const TcpHeader& h);                        // sender side
    std::uint32_t first_hole_limit() const; // sender: where the first unSACKed hole ends

    // --- teardown ---
    void enter_time_wait();
    void abort();
    bool can_receive() const noexcept;
    std::size_t inflight() const noexcept; // bytes sent but unacked (incl FIN)

    Tcp&      owner_;
    FourTuple tuple_;
    State     state_ = State::Closed;

    // Send sequence space.
    std::uint32_t snd_una_ = 0;
    std::uint32_t snd_nxt_ = 0;
    std::uint32_t snd_wnd_ = 0; // peer's advertised receive window (bytes)
    std::uint32_t iss_     = 0;
    // Effective send MSS: min(our MSS, the peer's advertised MSS option). We
    // segment outbound data to this so we never overshoot what the peer accepts.
    std::uint32_t snd_mss_ = 1460;

    // Receive sequence space.
    std::uint32_t rcv_nxt_ = 0;
    std::uint32_t irs_     = 0;

    // Send buffer: unacknowledged + unsent application bytes, starting at
    // snd_una_. A contiguous ring (not a std::deque) so segment extraction is a
    // memcpy, not a per-byte walk of non-contiguous storage (see send_ring.hpp).
    SendRing send_buf_;

    // Out-of-order received segments awaiting a gap fill (seq -> bytes).
    std::map<std::uint32_t, std::vector<std::byte>> ooo_;
    std::size_t ooo_bytes_ = 0;

    // FIN bookkeeping (FIN occupies one sequence number at the end of our data).
    bool          want_fin_ = false;
    bool          fin_sent_ = false;
    std::uint32_t fin_seq_  = 0;

    // RTT estimator (Jacobson/Karels), all in milliseconds.
    double        srtt_ms_   = 0.0;
    double        rttvar_ms_ = 0.0;
    double        rto_ms_    = 1000.0;
    bool          first_rtt_ = true;
    bool          rtt_timing_ = false;
    std::uint32_t rtt_seq_    = 0;      // we're timing the ack of this sequence
    net::TimePoint rtt_start_{};

    // Congestion control (Reno).
    std::uint32_t cwnd_          = 0;
    std::uint32_t ssthresh_      = 0;
    std::uint32_t dup_acks_      = 0;
    bool          in_fast_recovery_ = false;

    // SACK (RFC 2018). sack_ok_ is set once both sides offered SACK-permitted.
    // sacked_ holds the peer-SACKed ranges above snd_una (sender side), kept
    // sorted and merged, so retransmission skips data the peer already has.
    bool                   offer_sack_ = true;  // include SACK-permitted in our SYN
    bool                   sack_ok_ = false;
    std::vector<SackBlock> sacked_;

    // Timers.
    net::TimerId rto_timer_       = 0;
    net::TimerId time_wait_timer_ = 0;
    net::TimerId persist_timer_   = 0;
    bool         rto_running_     = false;
    bool         persist_running_ = false;
    double       persist_ms_      = 1000.0;

    // Flags / stats.
    bool          close_notified_ = false;
    bool          finished_       = false;
    std::uint64_t retransmits_      = 0;
    std::uint64_t fast_retransmits_ = 0;
    std::uint64_t rto_events_       = 0;
};

} // namespace tcp
