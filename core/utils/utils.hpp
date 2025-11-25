#ifndef UTILS_HPP
#define UTILS_HPP
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <shared_mutex>

namespace utils
{

    class safeHandle {
    public:
        safeHandle(HANDLE handle)
            : m_data(handle ? std::make_shared<handleData>(handle) : nullptr) {
        }

        safeHandle(const safeHandle&) = default;
        safeHandle(safeHandle&&) noexcept = default;
        safeHandle& operator=(const safeHandle&) = default;
        safeHandle& operator=(safeHandle&&) noexcept = default;

        ~safeHandle() = default;

        operator HANDLE() const {
            return m_data ? m_data->handle : INVALID_HANDLE_VALUE;
        }

        operator bool() const {
            return m_data && m_data->handle != INVALID_HANDLE_VALUE;
        }

        void close() {
            if (m_data && m_data.use_count() == 1) {
                CloseHandle(m_data->handle);
            }
            m_data.reset();
        }

        HANDLE* getAddress() {
            if (!m_data)
                m_data = std::make_shared<handleData>(INVALID_HANDLE_VALUE);
            return &m_data->handle;
        }

    private:
        struct handleData {
            HANDLE handle;
            explicit handleData(HANDLE h) : handle(h) {}
            ~handleData() {
                if (handle && handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(handle);
                }
            }
        };

        std::shared_ptr<handleData> m_data;
    };

	template <class T>
	class threadSafeVector {
	public:
		threadSafeVector() = default;
		explicit threadSafeVector(std::vector<T> init) {
			std::unique_lock lock(m_);
			v_ = std::move(init);
		}

		threadSafeVector(const threadSafeVector& other) {
			std::shared_lock lock(other.m_);
			v_ = other.v_;
		}
		threadSafeVector& operator=(const threadSafeVector& other) {
			if (this == &other) return *this;
			std::scoped_lock lock(m_, other.m_);
			v_ = other.v_;
			return *this;
		}
		threadSafeVector(threadSafeVector&& other) noexcept {
			std::unique_lock lock(other.m_);
			v_ = std::move(other.v_);
		}
		threadSafeVector& operator=(threadSafeVector&& other) noexcept {
			if (this == &other) return *this;
			std::scoped_lock lock(m_, other.m_);
			v_ = std::move(other.v_);
			return *this;
		}

		void push_back(T value) {
			std::unique_lock lock(m_);
			v_.push_back(std::move(value));
		}

		template <class... Args>
		std::size_t emplace_back(Args&&... args) {
			std::unique_lock lock(m_);
			v_.emplace_back(std::forward<Args>(args)...);
			return v_.size() - 1;
		}

		std::optional<T> pop_back() {
			std::unique_lock lock(m_);
			if (v_.empty()) return std::nullopt;
			T out = std::move(v_.back());
			v_.pop_back();
			return out;
		}

		void clear() {
			std::unique_lock lock(m_);
			v_.clear();
		}

		bool erase_index(std::size_t idx) {
			std::unique_lock lock(m_);
			if (idx >= v_.size()) return false;
			v_.erase(v_.begin() + static_cast<std::ptrdiff_t>(idx));
			return true;
		}

		template <class Pred>
		std::size_t remove_if(Pred&& p) {
			std::unique_lock lock(m_);
			const auto old = v_.size();
			v_.erase(std::remove_if(v_.begin(), v_.end(), std::forward<Pred>(p)), v_.end());
			return old - v_.size();
		}

		bool set(std::size_t idx, T value) {
			std::unique_lock lock(m_);
			if (idx >= v_.size()) return false;
			v_[idx] = std::move(value);
			return true;
		}

		std::size_t size() const {
			std::shared_lock lock(m_);
			return v_.size();
		}

		bool empty() const {
			std::shared_lock lock(m_);
			return v_.empty();
		}

		std::optional<T> get(std::size_t idx) const {
			std::shared_lock lock(m_);
			if (idx >= v_.size()) return std::nullopt;
			return v_[idx];
		}

		std::vector<T> snapshot() const {
			std::shared_lock lock(m_);
			return v_;
		}

		template <class F>
		decltype(auto) with_read_lock(F&& f) const {
			std::shared_lock lock(m_);
			return std::invoke(std::forward<F>(f), static_cast<const std::vector<T>&>(v_));
		}

		template <class F>
		decltype(auto) with_write_lock(F&& f) {
			std::unique_lock lock(m_);
			return std::invoke(std::forward<F>(f), v_);
		}

	private:
		mutable std::shared_mutex m_;
		std::vector<T> v_;
	};

}

#endif