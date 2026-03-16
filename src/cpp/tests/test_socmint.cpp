#include "socmint/types.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <cmath>
using namespace socmint;

void testSerialization() {
    std::vector<SocialRecord> records;
    SocialRecord r{};
    std::strncpy(r.post_id, "1773264604", 23);
    std::strncpy(r.author_handle, "@christostzamos", 23);
    r.epoch_s = 1773264604;
    r.lat_deg = NAN; r.lon_deg = NAN;
    r.likes = 2008; r.reposts = 500; r.views = 50000;
    r.platform = static_cast<uint8_t>(Platform::TWITTER);
    r.content_type = static_cast<uint8_t>(ContentType::VIDEO);
    r.sentiment = static_cast<uint8_t>(Sentiment::POSITIVE);
    r.intel_flags = static_cast<uint8_t>(IntelFlag::BREAKING);
    records.push_back(r);

    SocialRecord r2{};
    std::strncpy(r2.post_id, "tiktok_12345", 23);
    r2.lat_deg = 50.0; r2.lon_deg = 36.0; // Geolocated
    r2.platform = static_cast<uint8_t>(Platform::TIKTOK);
    r2.intel_flags = static_cast<uint8_t>(IntelFlag::GEOLOCATION) |
                     static_cast<uint8_t>(IntelFlag::MILITARY);
    records.push_back(r2);

    auto buf = serialize(records);
    assert(std::memcmp(buf.data(), "$SOC", 4) == 0);
    SOCHeader hdr; std::vector<SocialRecord> dec;
    assert(deserialize(buf.data(), buf.size(), hdr, dec));
    assert(dec.size() == 2);
    std::cout << "  Serialization ✓ (" << buf.size() << " bytes)\n";
}

void testFilters() {
    std::vector<SocialRecord> records;
    auto mk = [](Platform p, double lat, double lon, uint32_t views, uint8_t flags) {
        SocialRecord r{}; r.platform = static_cast<uint8_t>(p);
        r.lat_deg = lat; r.lon_deg = lon; r.views = views; r.intel_flags = flags;
        return r;
    };
    records.push_back(mk(Platform::TWITTER, NAN, NAN, 50000, 128));
    records.push_back(mk(Platform::TIKTOK, 50, 36, 100, 3));
    records.push_back(mk(Platform::TELEGRAM, 48, 38, 500, 8));
    records.push_back(mk(Platform::REDDIT, NAN, NAN, 15000, 0));

    assert(filterByPlatform(records, Platform::TWITTER).size() == 1);
    assert(filterGeolocated(records).size() == 2);
    assert(filterByIntelFlag(records, IntelFlag::MOVEMENT).size() == 1);
    assert(filterViral(records, 10000).size() == 2);
    std::cout << "  Filters ✓\n";
}

int main() {
    std::cout << "=== socmint-sdn-plugin tests ===\n";
    testSerialization(); testFilters();
    std::cout << "All SOCMINT tests passed.\n"; return 0;
}
