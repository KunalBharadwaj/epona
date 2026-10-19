#include "tcp/tcp_connection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>

#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"
#include "tcp/seq.hpp"
#include "tcp/tcp.hpp"
#include "tcp/tcp_trace.hpp"

namespace tcp {

namespace {
constexpr std::uint32_t kMss            = 1460;
constexpr std::uint32_t kInitialCwnd    = 10 * kMss;     // RFC 6928 initial window (IW10)
constexpr std::uint32_t kInitialSsthresh = 64 * 1024;
constexpr std::uint32_t kAdvWindow      = 65535;        // what we advertise (stable)
constexpr std::uint32_t kOooCap         = 256 * 1024;   // reassembly headroom > window
constexpr std::uint32_t kDupAckThresh   = 3;
constexpr std::uint32_t kCwndCap        = 16u * 1024 * 1024;
constexpr double        kMinRtoMs       = 200.0;
constexpr double        kMaxRtoMs       = 60000.0;
constexpr double        kInitialRtoMs   = 1000.0;

std::uint32_t random_iss() {
    auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<std::uint32_t>(ns) * 2654435761u + 1u;
}

double now_ms_since(net::TimePoint start) {
    using namespace std::chrono;
    return duration_cast<duration<double, std::milli>>(net::Clock::now() - start).count();
}

// SACK is on by default; set TCPSTACK_NOSACK=1 to negotiate it off (handy for
// before/after loss measurements). Read once, then cached.
bool sack_enabled() {
    static const bool enabled = (std::getenv("TCPSTACK_NOSACK") == nullptr);
    return enabled;
}
} // namespace

const char* to_string(State s) noexcept {
    switch (s) {
    case State::SynSent:     return "SYN-SENT";
    case State::SynReceived: return "SYN-RECEIVED";
    case State::Established:  return "ESTABLISHED";
    case State::FinWait1:     return "FIN-WAIT-1";
    case State::FinWait2:     return "FIN-WAIT-2";
    case State::CloseWait:    return "CLOSE-WAIT";
    case State::Closing:      return "CLOSING";
    case State::LastAck:      return "LAST-ACK";
    case State::TimeWait:     return "TIME-WAIT";
    case State::Closed:       return "CLOSED";
    }
    return "?";
}

TcpConnection::TcpConnection(Tcp& owner, FourTuple tuple)
    : owner_(owner), tuple_(tuple) {}

TcpConnection::~TcpConnection() {
    // Never leave a timer pointing at a freed connection.
    disarm_rto();
    disarm_persist();
    if (time_wait_timer_) owner_.loop().cancel_timer(time_wait_timer_);
}

bool TcpConnection::can_receive() const noexcept {
    return state_ == State::Established || state_ == State::FinWait1 ||
           state_ == State::FinWait2;
}

std::size_t TcpConnection::inflight() const noexcept {
    return static_cast<std::size_t>(snd_nxt_ - snd_una_);
}

std::uint16_t TcpConnection::advertised_window() const {
    // We deliver in-order data to the app synchronously (on_data), so the only
    // thing we hold is out-of-order data for reassembly. We advertise a STABLE
    // window (a window that shrank as we buffered out-of-order segments would
    // make our duplicate ACKs look like window updates to the peer, defeating
    // its fast-retransmit). The OOO buffer has headroom well beyond this window
    // (kOooCap > kAdvWindow), so we can always hold a full window of out-of-
    // order data without dropping anything we advertised room for.
    return static_cast<std::uint16_t>(kAdvWindow);
}

// ---------------------------------------------------------------------------
// Transmission
// ---------------------------------------------------------------------------
void TcpConnection::send_raw(std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                             std::span<const std::byte> payload, bool with_mss) {
    // Build the options region (must end 4-byte aligned).
    std::array<std::byte, 40> opt{};
    std::size_t olen = 0;
    auto put8  = [&](std::uint8_t b) { opt[olen++] = std::byte{b}; };
    auto put32 = [&](std::uint32_t v) {
        put8(static_cast<std::uint8_t>(v >> 24)); put8(static_cast<std::uint8_t>(v >> 16));
        put8(static_cast<std::uint8_t>(v >> 8));  put8(static_cast<std::uint8_t>(v));
    };

    if (with_mss) {
        // SYN: advertise our MSS, and offer SACK if appropriate.
        put8(opt::kMss); put8(4);
        put8(static_cast<std::uint8_t>(kMss >> 8)); put8(static_cast<std::uint8_t>(kMss & 0xFF));
        if (offer_sack_) { put8(opt::kSackPermitted); put8(2); put8(opt::kNop); put8(opt::kNop); }
    } else if (sack_ok_ && !(flags & flag::SYN) && !(flags & flag::RST) && !ooo_.empty()) {
        // Data ACK while holding out-of-order data: tell the peer exactly what
        // we have so it can selectively retransmit only the holes.
        std::array<SackBlock, 3> blk;
        std::uint8_t n = build_sack_blocks(blk);
        if (n > 0) {
            put8(opt::kNop); put8(opt::kNop); // align the SACK option
            put8(opt::kSack); put8(static_cast<std::uint8_t>(2 + 8 * n));
            for (std::uint8_t i = 0; i < n; ++i) { put32(blk[i].left); put32(blk[i].right); }
        }
    }

    net::PacketBuffer buf;
    net::NetWriter w(buf.capacity_span());
    std::size_t header_len = kTcpMinHeader + olen;

    w.u16(tuple_.local_port);
    w.u16(tuple_.remote_port);
    w.u32(seq);
    w.u32(ack);
    w.u8(static_cast<std::uint8_t>((header_len / 4) << 4));
    w.u8(flags);
    w.u16(advertised_window());
    w.u16(0); // checksum placeholder
    w.u16(0); // urgent
    w.bytes(std::span<const std::byte>(opt.data(), olen));
    w.bytes(payload);
    if (!w.ok()) return;

    buf.set_size(w.offset());
    auto seg = buf.bytes();
    std::uint16_t cksum = ip::transport_checksum(tuple_.local_ip, tuple_.remote_ip,
                                                 ip::IpProto::Tcp, seg);
    seg[16] = std::byte{static_cast<std::uint8_t>(cksum >> 8)};
    seg[17] = std::byte{static_cast<std::uint8_t>(cksum & 0xFF)};
    trace_seg("OUT", tuple_.local_port, tuple_.remote_port, seq, ack, flags, payload.size());
    owner_.ip().send_ipv4(tuple_.remote_ip, ip::IpProto::Tcp, seg);
}

void TcpConnection::send_ack()  { send_raw(snd_nxt_, rcv_nxt_, flag::ACK); }
void TcpConnection::send_rst()  { send_raw(snd_nxt_, rcv_nxt_, flag::RST | flag::ACK); }

void TcpConnection::try_send() {
    if (state_ == State::Established || state_ == State::CloseWait ||
        state_ == State::FinWait1   || state_ == State::Closing) {
        while (true) {
            std::uint32_t awnd   = std::min(snd_wnd_, cwnd_);
            std::uint32_t flight = snd_nxt_ - snd_una_;
            if (flight >= awnd) break;                 // window full
            std::uint32_t usable = awnd - flight;

            std::size_t in_flight_data = std::min<std::size_t>(send_buf_.size(), flight);
            std::size_t unsent = send_buf_.size() - in_flight_data;
            if (unsent == 0) break;

            std::size_t seglen = std::min<std::size_t>({usable, unsent,
                                                        static_cast<std::size_t>(kMss)});
            if (seglen == 0) break;

            std::array<std::byte, kMss> tmp;
            send_buf_.copy_out(in_flight_data, tmp.data(), seglen);

            if (!rtt_timing_) { rtt_timing_ = true; rtt_seq_ = snd_nxt_; rtt_start_ = net::Clock::now(); }

            send_raw(snd_nxt_, rcv_nxt_, flag::ACK | flag::PSH,
                     std::span<const std::byte>(tmp.data(), seglen));
            snd_nxt_ += static_cast<std::uint32_t>(seglen);
            arm_rto();
        }

        // Zero-window: can't send but have data queued -> start persist probing.
        std::size_t in_flight_data = std::min<std::size_t>(send_buf_.size(), snd_nxt_ - snd_una_);
        if (send_buf_.size() - in_flight_data > 0 && std::min(snd_wnd_, cwnd_) <= (snd_nxt_ - snd_una_)) {
            if (snd_wnd_ == 0) arm_persist();
        }
    }
    send_fin_if_ready();
}

void TcpConnection::send_fin_if_ready() {
    if (!want_fin_ || fin_sent_) return;
    std::size_t in_flight_data = std::min<std::size_t>(send_buf_.size(), snd_nxt_ - snd_una_);
    if (send_buf_.size() - in_flight_data != 0) return; // data still queued; FIN waits

    fin_seq_ = snd_nxt_;
    send_raw(snd_nxt_, rcv_nxt_, flag::FIN | flag::ACK);
    snd_nxt_ += 1;
    fin_sent_ = true;
    arm_rto();
}

void TcpConnection::retransmit_oldest() {
    // Karn's algorithm: a retransmitted segment can't be used for an RTT sample.
    rtt_timing_ = false;

    if (!send_buf_.empty()) {
        // With SACK, only resend the first hole: data up to the next range the
        // peer has already SACKed, so we never retransmit what it already holds.
        std::uint32_t limit = first_hole_limit(); // <= snd_nxt_
        std::size_t hole = seq_gt(limit, snd_una_)
                               ? static_cast<std::size_t>(limit - snd_una_)
                               : send_buf_.size();
        std::size_t len = std::min<std::size_t>({static_cast<std::size_t>(kMss),
                                                 send_buf_.size(), hole});
        if (len == 0) len = std::min<std::size_t>(send_buf_.size(), kMss);
        std::array<std::byte, kMss> tmp;
        send_buf_.copy_out(0, tmp.data(), len);
        send_raw(snd_una_, rcv_nxt_, flag::ACK | flag::PSH,
                 std::span<const std::byte>(tmp.data(), len));
    } else if (fin_sent_ && snd_una_ != snd_nxt_) {
        // Only the FIN is outstanding.
        send_raw(snd_una_, rcv_nxt_, flag::FIN | flag::ACK);
    }
}

// ---------------------------------------------------------------------------
// SACK (RFC 2018)
// ---------------------------------------------------------------------------
std::uint8_t TcpConnection::build_sack_blocks(std::array<SackBlock, 3>& out) const {
    // Merge the out-of-order map into contiguous runs (ooo_ is sorted by seq).
    std::vector<SackBlock> runs;
    for (const auto& [seq, bytes] : ooo_) {
        std::uint32_t l = seq;
        std::uint32_t r = seq + static_cast<std::uint32_t>(bytes.size());
        if (!runs.empty() && runs.back().right == l) runs.back().right = r;
        else runs.push_back(SackBlock{l, r});
    }
    // Report the most recent (highest-seq) run first, per RFC 2018.
    std::uint8_t n = 0;
    for (auto it = runs.rbegin(); it != runs.rend() && n < 3; ++it) out[n++] = *it;
    return n;
}

void TcpConnection::record_sack(const TcpHeader& h) {
    if (!sack_ok_) return;
    for (std::uint8_t i = 0; i < h.sack_count; ++i) {
        std::uint32_t l = h.sack_blocks[i].left;
        std::uint32_t r = h.sack_blocks[i].right;
        if (!seq_lt(l, r)) continue;                 // invalid block
        if (seq_lt(l, snd_una_)) l = snd_una_;       // clamp to our send window
        if (seq_gt(r, snd_nxt_)) r = snd_nxt_;
        if (seq_lt(l, r)) sacked_.push_back(SackBlock{l, r});
    }
    // Drop/trim anything at or below snd_una, then sort and merge.
    std::vector<SackBlock> keep;
    for (auto& b : sacked_) {
        std::uint32_t l = seq_lt(b.left, snd_una_) ? snd_una_ : b.left;
        if (seq_lt(l, b.right) && seq_gt(b.right, snd_una_)) keep.push_back(SackBlock{l, b.right});
    }
    std::sort(keep.begin(), keep.end(),
              [](const SackBlock& a, const SackBlock& b) { return seq_lt(a.left, b.left); });
    sacked_.clear();
    for (auto& b : keep) {
        if (!sacked_.empty() && seq_leq(b.left, sacked_.back().right)) {
            if (seq_gt(b.right, sacked_.back().right)) sacked_.back().right = b.right;
        } else {
            sacked_.push_back(b);
        }
    }
}

std::uint32_t TcpConnection::first_hole_limit() const {
    std::uint32_t limit = snd_nxt_;
    for (const auto& b : sacked_) {
        if (seq_gt(b.left, snd_una_) && seq_lt(b.left, limit)) limit = b.left;
    }
    return limit;
}

// ---------------------------------------------------------------------------
// Opens
// ---------------------------------------------------------------------------
void TcpConnection::passive_open(const TcpHeader& syn) {
    // Mirror SACK only if the peer offered it (and we have it enabled).
    offer_sack_ = syn.sack_permitted && sack_enabled();
    sack_ok_    = offer_sack_;

    irs_      = syn.seq;
    rcv_nxt_  = syn.seq + 1;
    iss_      = random_iss();
    snd_una_  = iss_;
    snd_wnd_  = syn.window;
    cwnd_     = kInitialCwnd;
    ssthresh_ = kInitialSsthresh;
    rto_ms_   = kInitialRtoMs;
    state_    = State::SynReceived;

    send_raw(iss_, rcv_nxt_, flag::SYN | flag::ACK, {}, /*with_mss=*/true);
    snd_nxt_ = iss_ + 1;
}

void TcpConnection::active_open() {
    offer_sack_ = sack_enabled();
    iss_      = random_iss();
    snd_una_  = iss_;
    cwnd_     = kInitialCwnd;
    ssthresh_ = kInitialSsthresh;
    rto_ms_   = kInitialRtoMs;
    state_    = State::SynSent;

    send_raw(iss_, 0, flag::SYN, {}, /*with_mss=*/true);
    snd_nxt_ = iss_ + 1;
}

// ---------------------------------------------------------------------------
// App API
// ---------------------------------------------------------------------------
void TcpConnection::send(std::span<const std::byte> data) {
    if (data.empty()) return;
    if (state_ != State::Established && state_ != State::CloseWait) return;
    send_buf_.append(data);
    try_send();
}

void TcpConnection::close() {
    switch (state_) {
    case State::Established: want_fin_ = true; state_ = State::FinWait1; try_send(); break;
    case State::CloseWait:   want_fin_ = true; state_ = State::LastAck;  try_send(); break;
    default: break;
    }
}

// ---------------------------------------------------------------------------
// Inbound processing
// ---------------------------------------------------------------------------
void TcpConnection::handle_syn_sent(const TcpHeader& h, std::span<const std::byte>) {
    if (h.has(flag::RST)) { abort(); return; }
    if (!h.has(flag::SYN)) return;

    irs_     = h.seq;
    rcv_nxt_ = h.seq + 1;
    snd_wnd_ = h.window;

    if (h.has(flag::ACK)) {
        if (h.ack != snd_nxt_) { send_raw(h.ack, 0, flag::RST); return; }
        sack_ok_ = offer_sack_ && h.sack_permitted; // negotiation complete
        snd_una_ = h.ack;
        state_   = State::Established;
        send_ack();
        if (on_open) on_open(*this);
    } else {
        state_ = State::SynReceived;
        send_raw(iss_, rcv_nxt_, flag::SYN | flag::ACK, {}, true);
    }
}

void TcpConnection::process_ack(const TcpHeader& h, std::size_t data_len) {
    if (seq_gt(h.ack, snd_nxt_)) { send_ack(); return; } // acks unsent data

    // Record any SACK blocks first, so a duplicate ACK carrying new SACK info
    // steers retransmit_oldest() to the actual hole.
    record_sack(h);

    // Duplicate ACK: no advance, no data, and we still have data in flight.
    const bool is_dup = (h.ack == snd_una_) && (data_len == 0) &&
                        (snd_una_ != snd_nxt_) && !h.has(flag::SYN) && !h.has(flag::FIN);
    if (is_dup) {
        snd_wnd_ = h.window;
        ++dup_acks_;
        if (in_fast_recovery_) {
            cwnd_ = std::min(cwnd_ + kMss, kCwndCap); // inflate per RFC 5681
            try_send();
        } else if (dup_acks_ == kDupAckThresh) {
            ++fast_retransmits_;
            owner_.note_fast_retransmit();
            enter_loss_recovery(/*fast=*/true);
            retransmit_oldest();
        }
        return;
    }

    if (seq_gt(h.ack, snd_una_)) {
        // New data acknowledged.
        if (rtt_timing_ && seq_gt(h.ack, rtt_seq_)) {
            update_rtt(now_ms_since(rtt_start_));
            rtt_timing_ = false;
        }
        std::uint32_t acked = h.ack - snd_una_;
        snd_una_ = h.ack;
        std::size_t data_acked = std::min<std::size_t>(acked, send_buf_.size());
        send_buf_.pop_front(data_acked);
        snd_wnd_ = h.window;
        dup_acks_ = 0;
        // Grow the congestion window on acknowledged DATA only — the SYN and FIN
        // each consume a sequence number but aren't data.
        on_new_ack(static_cast<std::uint32_t>(data_acked));

        if (snd_una_ == snd_nxt_) disarm_rto(); else arm_rto();
        if (snd_wnd_ > 0) disarm_persist();
        try_send();
    } else {
        snd_wnd_ = h.window; // pure window update / old ack
        if (snd_wnd_ > 0) disarm_persist();
    }
}

void TcpConnection::deliver_in_order(std::uint32_t seq, std::span<const std::byte> data) {
    // Trim any prefix we've already delivered.
    if (seq_lt(seq, rcv_nxt_)) {
        owner_.note_rx_retransmit(); // peer retransmitted data we already have
        std::uint32_t skip = rcv_nxt_ - seq;
        if (skip >= data.size()) return; // fully duplicate
        data = data.subspan(skip);
        seq  = rcv_nxt_;
    }

    if (seq == rcv_nxt_) {
        rcv_nxt_ += static_cast<std::uint32_t>(data.size());
        if (on_data) on_data(*this, data);
        // Pull any now-contiguous buffered segments.
        for (;;) {
            auto it = ooo_.begin();
            if (it == ooo_.end()) break;
            std::uint32_t s = it->first;
            if (seq_gt(s, rcv_nxt_)) break;       // still a gap
            std::vector<std::byte> bytes = std::move(it->second);
            ooo_bytes_ -= bytes.size();
            ooo_.erase(it);
            std::span<const std::byte> span{bytes};
            if (seq_lt(s, rcv_nxt_)) {             // overlap already delivered
                std::uint32_t skip = rcv_nxt_ - s;
                if (skip >= span.size()) continue;
                span = span.subspan(skip);
            }
            rcv_nxt_ += static_cast<std::uint32_t>(span.size());
            if (on_data) on_data(*this, span);
        }
    } else if (seq_gt(seq, rcv_nxt_)) {
        // Future segment: buffer it (within our receive window) for reassembly.
        if (!ooo_.count(seq) && ooo_bytes_ + data.size() <= kOooCap) {
            ooo_.emplace(seq, std::vector<std::byte>(data.begin(), data.end()));
            ooo_bytes_ += data.size();
            owner_.note_ooo();
        }
    }
}

void TcpConnection::handle_fin() {
    switch (state_) {
    case State::Established: state_ = State::CloseWait; break;
    case State::FinWait1:    state_ = State::Closing;   break;
    case State::FinWait2:    enter_time_wait();         break;
    default: break;
    }
    if (!close_notified_) {
        close_notified_ = true;
        if (on_close) on_close(*this);
    }
}

void TcpConnection::on_segment(const TcpHeader& h, std::span<const std::byte> data) {
    if (state_ == State::SynSent) { handle_syn_sent(h, data); return; }

    if (h.has(flag::RST)) { if (h.seq == rcv_nxt_) abort(); return; }

    if (h.has(flag::SYN)) {
        if (state_ == State::SynReceived && h.seq == irs_)
            send_raw(iss_, rcv_nxt_, flag::SYN | flag::ACK, {}, true); // retransmit
        else { send_rst(); abort(); }
        return;
    }

    if (!h.has(flag::ACK)) return;

    const std::uint32_t fin_pos = h.seq + static_cast<std::uint32_t>(data.size());
    process_ack(h, data.size());
    if (finished_) return;

    // ACK-driven state transitions.
    const bool our_fin_acked = fin_sent_ && seq_geq(snd_una_, fin_seq_ + 1);
    switch (state_) {
    case State::SynReceived:
        if (snd_una_ == snd_nxt_) { state_ = State::Established; owner_.notify_accept(*this); try_send(); }
        break;
    case State::FinWait1: if (our_fin_acked) state_ = State::FinWait2; break;
    case State::Closing:  if (our_fin_acked) enter_time_wait(); break;
    case State::LastAck:  if (our_fin_acked) { state_ = State::Closed; finished_ = true; return; }
    default: break;
    }

    bool need_ack = false;
    if (!data.empty() && can_receive()) {
        std::uint32_t rcv_before = rcv_nxt_;
        std::uint32_t snd_before = snd_nxt_;
        deliver_in_order(h.seq, data);

        if (rcv_nxt_ == rcv_before) {
            // Out-of-order: we must send a (duplicate) ACK so the peer fast-
            // retransmits the gap instead of waiting for its RTO.
            owner_.note_dup_ack_sent();
            need_ack = true;
        } else if (snd_nxt_ == snd_before) {
            // We advanced but the app sent nothing to piggyback the ACK on.
            need_ack = true;
        }
        // Otherwise the app's reply (e.g. echo) already carried the ACK, so we
        // skip the redundant bare ACK.
    }

    if (h.has(flag::FIN) && fin_pos == rcv_nxt_ && can_receive()) {
        rcv_nxt_ += 1;
        need_ack = true;
        handle_fin();
    }

    if (need_ack) send_ack();
}

// ---------------------------------------------------------------------------
// RTT / RTO (Jacobson/Karels)
// ---------------------------------------------------------------------------
void TcpConnection::update_rtt(double r) {
    if (first_rtt_) {
        srtt_ms_   = r;
        rttvar_ms_ = r / 2.0;
        first_rtt_ = false;
    } else {
        rttvar_ms_ = 0.75 * rttvar_ms_ + 0.25 * std::fabs(srtt_ms_ - r);
        srtt_ms_   = 0.875 * srtt_ms_ + 0.125 * r;
    }
    rto_ms_ = std::clamp(srtt_ms_ + 4.0 * rttvar_ms_, kMinRtoMs, kMaxRtoMs);
}

void TcpConnection::arm_rto() {
    disarm_rto();
    auto d = net::Duration(static_cast<long long>(std::llround(rto_ms_)));
    rto_timer_ = owner_.loop().add_timer(d, [this] { on_rto(); });
    rto_running_ = true;
}

void TcpConnection::disarm_rto() {
    if (rto_running_) { owner_.loop().cancel_timer(rto_timer_); rto_running_ = false; }
}

void TcpConnection::on_rto() {
    rto_running_ = false;
    if (snd_una_ == snd_nxt_) return; // nothing outstanding
    ++rto_events_;
    ++retransmits_;
    owner_.note_retransmit();

    enter_loss_recovery(/*fast=*/false); // ssthresh = flight/2, cwnd = 1 MSS
    rto_ms_ = std::min(rto_ms_ * 2.0, kMaxRtoMs); // exponential backoff
    retransmit_oldest();
    arm_rto();
}

// ---------------------------------------------------------------------------
// Zero-window persist
// ---------------------------------------------------------------------------
void TcpConnection::arm_persist() {
    if (persist_running_) return;
    auto d = net::Duration(static_cast<long long>(std::llround(persist_ms_)));
    persist_timer_ = owner_.loop().add_timer(d, [this] { on_persist(); });
    persist_running_ = true;
}

void TcpConnection::disarm_persist() {
    if (persist_running_) { owner_.loop().cancel_timer(persist_timer_); persist_running_ = false; }
    persist_ms_ = 1000.0;
}

void TcpConnection::on_persist() {
    persist_running_ = false;
    std::size_t in_flight_data = std::min<std::size_t>(send_buf_.size(), snd_nxt_ - snd_una_);
    if (snd_wnd_ != 0 || send_buf_.size() - in_flight_data == 0) return;

    // Probe with one byte beyond the window to force a window update.
    std::byte probe = send_buf_.at(in_flight_data);
    send_raw(snd_nxt_, rcv_nxt_, flag::ACK, std::span<const std::byte>(&probe, 1));
    snd_nxt_ += 1;
    arm_rto();

    persist_ms_ = std::min(persist_ms_ * 2.0, 60000.0); // back off
    arm_persist();
}

// ---------------------------------------------------------------------------
// Congestion control (Reno)
// ---------------------------------------------------------------------------
void TcpConnection::enter_loss_recovery(bool fast) {
    std::uint32_t flight = snd_nxt_ - snd_una_;
    std::uint32_t half   = std::max(flight / 2, 2 * kMss);
    ssthresh_ = half;
    if (fast) {
        cwnd_ = std::min(ssthresh_ + 3 * kMss, kCwndCap);
        in_fast_recovery_ = true;
    } else {
        cwnd_ = kMss;
        in_fast_recovery_ = false;
        dup_acks_ = 0;
    }
}

void TcpConnection::on_new_ack(std::uint32_t acked) {
    if (in_fast_recovery_) {
        cwnd_ = ssthresh_;            // deflate on recovery exit
        in_fast_recovery_ = false;
        return;
    }
    if (cwnd_ < ssthresh_) {
        cwnd_ = std::min(cwnd_ + std::min(acked, kMss), kCwndCap);  // slow start
    } else {
        std::uint32_t inc = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(kMss) * kMss) / std::max<std::uint32_t>(cwnd_, 1));
        cwnd_ = std::min(cwnd_ + std::max<std::uint32_t>(inc, 1), kCwndCap); // AIMD
    }
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------
void TcpConnection::enter_time_wait() {
    state_ = State::TimeWait;
    disarm_rto();
    disarm_persist();
    FourTuple t = tuple_;
    Tcp* owner = &owner_;
    time_wait_timer_ = owner_.loop().add_timer(owner_.time_wait(),
                                               [owner, t] { owner->remove(t); });
}

void TcpConnection::abort() {
    state_    = State::Closed;
    finished_ = true;
    disarm_rto();
    disarm_persist();
    if (!close_notified_) { close_notified_ = true; if (on_close) on_close(*this); }
}

} // namespace tcp
