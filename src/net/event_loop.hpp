#pragma once
//
// The event loop: one epoll instance, one thread, driving the whole stack.
//
// Structure (straight from the guide):
//   1. compute how long until the next timer fires
//   2. epoll_wait up to that long for any readable fd
//   3. dispatch each readable fd to its handler
//   4. service every timer that has now expired
//
// Keeping it single-threaded means no locks and easy-to-reason-about state --
// which matters enormously once the TCP state machine and retransmission timers
// land. Timers here will later drive RTO retransmits, TIME-WAIT, and keepalive.
//
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <queue>
#include <unordered_map>
#include <vector>

namespace net {

using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration  = std::chrono::milliseconds;

using TimerId = std::uint64_t;

class EventLoop {
public:
    using ReadHandler  = std::function<void()>;
    using TimerHandler = std::function<void()>;

    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop&)            = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    // Register `fd` for readability. `handler` is called whenever epoll reports
    // the fd is readable. We use level-triggered epoll so a handler that reads
    // one frame per wake-up still makes progress.
    void add_readable(int fd, ReadHandler handler);
    void remove_fd(int fd);

    // Schedule `handler` to run once after `delay`. Returns an id for cancel.
    TimerId add_timer(Duration delay, TimerHandler handler);
    void    cancel_timer(TimerId id);

    // Run until stop() is called. stop() is async-signal-safe (an atomic store
    // on a lock-free bool), so a signal handler may call it directly.
    void run();
    void stop() noexcept { running_.store(false); }

private:
    Duration time_until_next_timer() const;
    void     service_timers();

    struct ScheduledTimer {
        TimePoint when;
        TimerId   id;
        // Min-heap: earliest `when` on top.
        bool operator>(const ScheduledTimer& o) const { return when > o.when; }
    };

    int               epoll_fd_ = -1;
    std::atomic<bool> running_{false};

    std::unordered_map<int, ReadHandler> read_handlers_;

    // Pending timers in a min-heap, with callbacks kept separately so we can
    // cancel lazily: cancel() erases the callback; the heap entry is skipped
    // when it surfaces with no matching callback.
    std::priority_queue<ScheduledTimer, std::vector<ScheduledTimer>,
                        std::greater<ScheduledTimer>> timer_heap_;
    std::unordered_map<TimerId, TimerHandler> timer_callbacks_;
    TimerId next_timer_id_ = 1;
};

} // namespace net
