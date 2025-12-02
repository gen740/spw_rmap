#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <expected>
#include <thread>

#include "spw_rmap/transaction_database.hh"

namespace {

TEST(TransactionDatabaseTest, IssuesSequentialIdsAndReleases) {
  spw_rmap::TransactionDatabase db(0x10, 0x15);
  std::vector<uint16_t> ids;
  for (int i = 0; i < 5; ++i) {
    auto id = db.acquire();
    ASSERT_TRUE(id.has_value());
    ids.push_back(*id);
  }
  // Should wrap around after release.
  for (auto id : ids) {
    db.release(id);
  }
  for (int i = 0; i < 5; ++i) {
    auto id = db.acquire();
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, static_cast<uint16_t>(0x10 + i));
  }
}

TEST(TransactionDatabaseTest, CallbackReceivesPacket) {
  spw_rmap::TransactionDatabase db(0x20, 0x30);
  std::atomic<bool> called{false};

  uint16_t expected_id = 0;
  auto id = db.acquire(
      [&called, &expected_id](
          std::expected<spw_rmap::Packet, std::error_code> result) mutable
          -> void {
        ASSERT_TRUE(result.has_value());
        called = true;
        EXPECT_EQ(result->transactionID, expected_id);
      });
  ASSERT_TRUE(id.has_value());
  expected_id = *id;
  spw_rmap::Packet packet{};
  packet.transactionID = *id;
  EXPECT_TRUE(db.invokeReplyCallback(*id, packet));
  EXPECT_TRUE(called.load());
}

TEST(TransactionDatabaseTest, TimeoutInvokesCallbackWithError) {
  spw_rmap::TransactionDatabase db(0x40, 0x42);
  db.setTimeout(std::chrono::milliseconds(1));

  std::atomic<bool> timed_out{false};
  auto id = db.acquire(
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
    auto next = db.acquire();
    ASSERT_TRUE(next.has_value());
    later_ids.push_back(*next);
  }
  EXPECT_NE(std::ranges::find(later_ids, *id), later_ids.end());
  EXPECT_TRUE(timed_out.load());
}

}  // namespace
