#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <expected>
#include <mutex>
#include <thread>

#include "spw_rmap/transaction_database.hh"

namespace {

TEST(TransactionDatabaseTest, IssuesSequentialIdsAndReleases) {
  spw_rmap::TransactionDatabase db(0x10, 0x15);
  std::vector<uint16_t> ids;
  for (int i = 0; i < 5; ++i) {
    auto id = db.Acquire();
    ASSERT_TRUE(id.has_value());
    ids.push_back(*id);
  }
  // Should wrap around after release.
  for (auto id : ids) {
    db.Release(id);
  }
  for (int i = 0; i < 5; ++i) {
    auto id = db.Acquire();
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, static_cast<uint16_t>(0x10 + i));
  }
}

TEST(TransactionDatabaseTest, CallbackReceivesPacket) {
  spw_rmap::TransactionDatabase db(0x20, 0x30);
  std::atomic<bool> called{false};

  uint16_t expected_id = 0;
  auto id = db.Acquire(
      [&called, &expected_id](
          std::expected<spw_rmap::Packet, std::error_code> result) mutable
          -> void {
        ASSERT_TRUE(result.has_value());
        called = true;
        EXPECT_EQ(result->transaction_id, expected_id);
      });
  ASSERT_TRUE(id.has_value());
  expected_id = *id;
  spw_rmap::Packet packet{};
  packet.transaction_id = *id;
  EXPECT_TRUE(db.InvokeReplyCallback(*id, packet));
  EXPECT_TRUE(called.load());
}

TEST(TransactionDatabaseTest, TimeoutInvokesCallbackWithError) {
  spw_rmap::TransactionDatabase db(0x40, 0x42);
  db.SetTimeout(std::chrono::milliseconds(1));

  std::atomic<bool> timed_out{false};
  auto id = db.Acquire(
      [&timed_out](
          std::expected<spw_rmap::Packet, std::error_code> result) -> void {
        ASSERT_FALSE(result.has_value());
        timed_out = true;
        EXPECT_EQ(result.error(), std::make_error_code(std::errc::timed_out));
      });
  ASSERT_TRUE(id.has_value());

  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  std::vector<uint16_t> later_ids;
  const auto capacity = static_cast<int>(0x42 - 0x40);
  for (int i = 0; i < capacity; ++i) {
    auto next = db.Acquire();
    ASSERT_TRUE(next.has_value());
    later_ids.push_back(*next);
  }
  EXPECT_NE(std::ranges::find(later_ids, *id), later_ids.end());
  EXPECT_TRUE(timed_out.load());
}

TEST(TransactionDatabaseTest, ExhaustionReturnsResourceUnavailable) {
  spw_rmap::TransactionDatabase db(0x10, 0x13);

  ASSERT_TRUE(db.Acquire().has_value());
  ASSERT_TRUE(db.Acquire().has_value());
  ASSERT_TRUE(db.Acquire().has_value());
  auto exhausted = db.Acquire();

  ASSERT_FALSE(exhausted.has_value());
  EXPECT_EQ(exhausted.error(),
            std::make_error_code(std::errc::resource_unavailable_try_again));
}

TEST(TransactionDatabaseTest, InvalidReleaseDoesNotCorruptCapacity) {
  spw_rmap::TransactionDatabase db(0x10, 0x12);

  db.Release(0x0F);
  db.Release(0x12);

  EXPECT_TRUE(db.Acquire().has_value());
  EXPECT_TRUE(db.Acquire().has_value());
  EXPECT_FALSE(db.Acquire().has_value());
}

TEST(TransactionDatabaseTest, ReplyCallbackCanOnlyBeInvokedOnce) {
  spw_rmap::TransactionDatabase db(0x20, 0x22);
  std::atomic<int> callback_count{0};
  auto id = db.Acquire([&callback_count](auto) -> void { ++callback_count; });
  ASSERT_TRUE(id.has_value());
  spw_rmap::Packet packet{};
  packet.transaction_id = *id;

  EXPECT_TRUE(db.InvokeReplyCallback(*id, packet));
  EXPECT_FALSE(db.InvokeReplyCallback(*id, packet));
  EXPECT_EQ(callback_count.load(), 1);
}

TEST(TransactionDatabaseTest, ConcurrentAcquireReturnsUniqueIds) {
  constexpr int kThreadCount = 32;
  spw_rmap::TransactionDatabase db(0, kThreadCount);
  std::mutex results_mutex;
  std::vector<uint16_t> ids;
  std::vector<std::error_code> errors;
  std::vector<std::thread> threads;
  ids.reserve(kThreadCount);
  threads.reserve(kThreadCount);

  for (int i = 0; i < kThreadCount; ++i) {
    threads.emplace_back([&]() -> void {
      auto result = db.Acquire();
      std::lock_guard<std::mutex> lock(results_mutex);
      if (result.has_value()) {
        ids.push_back(*result);
      } else {
        errors.push_back(result.error());
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }

  ASSERT_TRUE(errors.empty());
  ASSERT_EQ(ids.size(), static_cast<std::size_t>(kThreadCount));
  std::ranges::sort(ids);
  EXPECT_EQ(std::ranges::unique(ids).begin(), ids.end());
  EXPECT_EQ(ids.front(), 0);
  EXPECT_EQ(ids.back(), kThreadCount - 1);
}

}  // namespace
