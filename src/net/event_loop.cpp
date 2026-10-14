#include "net/event_loop.hpp"

#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace net {

EventLoop::EventLoop() {
    epoll_fd_ = ::epoll_create1(0);
    if (epoll_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1 failed");
    }
}

EventLoop::~EventLoop() {
    if (epoll_fd_ >= 0) ::close(epoll_fd_);
}

void EventLoop::add_readable(int fd, ReadHandler handler) {
    epoll_event ev{};
    ev.events  = EPOLLIN;  // level-triggered
    ev.data.fd = fd;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(ADD) failed");
    }
    read_handlers_[fd] = std::move(handler);
}

void EventLoop::remove_fd(int fd) {
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    read_handlers_.erase(fd);
}

TimerId EventLoop::add_timer(Duration delay, TimerHandler handler) {
    TimerId id = next_timer_id_++;
    timer_heap_.push(ScheduledTimer{Clock::now() + delay, id});
    timer_callbacks_.emplace(id, std::move(handler));
    return id;
}

void EventLoop::cancel_timer(TimerId id) {
    // Lazy cancel: drop the callback; the heap entry is ignored when popped.
    timer_callbacks_.erase(id);
}

Duration EventLoop::time_until_next_timer() const {
    if (timer_callbacks_.empty()) {
        return Duration{-1}; // no timers -> epoll_wait blocks indefinitely
    }
    // Peek the earliest *live* timer. Cancelled ones are skipped here so we
    // don't wake up early for a timer nobody is waiting on.
    auto heap_copy = timer_heap_;
    while (!heap_copy.empty() &&
           timer_callbacks_.find(heap_copy.top().id) == timer_callbacks_.end()) {
        heap_copy.pop();
    }
    if (heap_copy.empty()) return Duration{-1};

    auto now = Clock::now();
    if (heap_copy.top().when <= now) return Duration{0};
    return std::chrono::duration_cast<Duration>(heap_copy.top().when - now);
}

void EventLoop::service_timers() {
    auto now = Clock::now();
    while (!timer_heap_.empty() && timer_heap_.top().when <= now) {
        ScheduledTimer t = timer_heap_.top();
        timer_heap_.pop();

        auto it = timer_callbacks_.find(t.id);
        if (it == timer_callbacks_.end()) continue; // cancelled

        TimerHandler cb = std::move(it->second);
        timer_callbacks_.erase(it);
        cb(); // may schedule new timers (e.g. the next retransmit)
    }
}

void EventLoop::run() {
    running_ = true;
    std::vector<epoll_event> events(64);

    while (running_) {
        Duration wait = time_until_next_timer();
        int timeout_ms = (wait.count() < 0)
                             ? -1
                             : static_cast<int>(wait.count());

        int n = ::epoll_wait(epoll_fd_, events.data(),
                             static_cast<int>(events.size()), timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue; // interrupted by a signal; retry
            throw std::system_error(errno, std::generic_category(), "epoll_wait failed");
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            auto it = read_handlers_.find(fd);
            if (it != read_handlers_.end()) {
                it->second();
            }
        }

        service_timers();
    }
}

} // namespace net
