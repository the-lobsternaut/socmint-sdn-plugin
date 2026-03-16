#ifndef SOCMINT_TYPES_H
#define SOCMINT_TYPES_H

/**
 * Social Media Intelligence (SOCMINT) Plugin Types
 * ===================================================
 *
 * Extracts structured intelligence from social media platforms.
 *
 * Data sources:
 *   1. X/Twitter API v2 (posts, users, trends)
 *   2. TikTok (metadata extraction — see hackers-arise.com OSINT guide)
 *   3. Telegram (channel monitoring)
 *   4. Reddit API (subreddit monitoring)
 *   5. Mastodon/Fediverse (ActivityPub)
 *
 * Output: $SOC FlatBuffer-aligned binary records
 *
 * Wire format:
 *   Header (16 bytes): magic[4]="$SOC", version(u32), source(u32), count(u32)
 *   N × SocialRecord (256 bytes each, packed)
 */

#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

namespace socmint {

static constexpr char SOC_FILE_ID[4] = {'$', 'S', 'O', 'C'};
static constexpr uint32_t SOC_VERSION = 1;

enum class Platform : uint8_t {
    TWITTER    = 0,
    TIKTOK     = 1,
    TELEGRAM   = 2,
    REDDIT     = 3,
    MASTODON   = 4,
    INSTAGRAM  = 5,
    FACEBOOK   = 6,
    YOUTUBE    = 7,
    DISCORD    = 8,
    LINKEDIN   = 9,
};

enum class ContentType : uint8_t {
    TEXT       = 0,
    IMAGE      = 1,
    VIDEO      = 2,
    LINK       = 3,
    POLL       = 4,
    REPOST     = 5,
    REPLY      = 6,
    STORY      = 7,
};

enum class Sentiment : uint8_t {
    UNKNOWN    = 0,
    POSITIVE   = 1,
    NEUTRAL    = 2,
    NEGATIVE   = 3,
    THREAT     = 4,  // Threat language detected
};

enum class IntelFlag : uint8_t {
    NONE            = 0,
    GEOLOCATION     = 1,   // Contains lat/lon (from metadata or text)
    MILITARY        = 2,   // Military-related content
    INFRASTRUCTURE  = 4,   // Critical infrastructure mentions
    MOVEMENT        = 8,   // Troop/vehicle/ship movement
    WEAPONS         = 16,  // Weapons identification
    PROPAGANDA      = 32,  // State propaganda patterns
    DISINFORMATION  = 64,  // Known disinfo patterns
    BREAKING        = 128, // First report / breaking news
};

#pragma pack(push, 1)

struct SOCHeader {
    char     magic[4];    // "$SOC"
    uint32_t version;
    uint32_t source;      // Platform enum
    uint32_t count;
};
static_assert(sizeof(SOCHeader) == 16, "SOCHeader must be 16 bytes");

/// Social media intelligence record
struct SocialRecord {
    // Identity
    char     post_id[24];      // Platform-specific post ID
    char     author_id[24];    // Author user ID
    char     author_handle[24];// @handle or username

    // Time
    double   epoch_s;          // Post timestamp [s]

    // Location (if available)
    double   lat_deg;          // Latitude (NAN if unknown)
    double   lon_deg;          // Longitude (NAN if unknown)

    // Content summary
    char     hashtags[48];     // Top hashtags, comma-separated
    char     mentions[24];     // Mentioned handles
    char     language[4];      // ISO 639-1 language code

    // Metrics
    uint32_t likes;
    uint32_t reposts;
    uint32_t replies;
    uint32_t views;

    // Classification
    uint8_t  platform;         // Platform enum
    uint8_t  content_type;     // ContentType enum
    uint8_t  sentiment;        // Sentiment enum
    uint8_t  intel_flags;      // IntelFlag bitfield

    // Media
    uint32_t media_count;      // Number of attached media items

    // Hash of content (for deduplication)
    uint64_t content_hash;

    uint8_t  reserved[4];
};
// Calculate actual size at compile time
static_assert(sizeof(SocialRecord) == 208, "SocialRecord size check");

#pragma pack(pop)

// ============================================================================
// Serialization
// ============================================================================

inline std::vector<uint8_t> serialize(const std::vector<SocialRecord>& records,
                                       Platform platform = Platform::TWITTER) {
    size_t size = sizeof(SOCHeader) + records.size() * sizeof(SocialRecord);
    std::vector<uint8_t> buf(size);

    SOCHeader hdr;
    std::memcpy(hdr.magic, SOC_FILE_ID, 4);
    hdr.version = SOC_VERSION;
    hdr.source = static_cast<uint32_t>(platform);
    hdr.count = static_cast<uint32_t>(records.size());
    std::memcpy(buf.data(), &hdr, sizeof(SOCHeader));

    if (!records.empty()) {
        std::memcpy(buf.data() + sizeof(SOCHeader),
                    records.data(), records.size() * sizeof(SocialRecord));
    }
    return buf;
}

inline bool deserialize(const uint8_t* data, size_t len,
                         SOCHeader& hdr, std::vector<SocialRecord>& records) {
    if (len < sizeof(SOCHeader)) return false;
    std::memcpy(&hdr, data, sizeof(SOCHeader));
    if (std::memcmp(hdr.magic, SOC_FILE_ID, 4) != 0) return false;
    size_t expected = sizeof(SOCHeader) + hdr.count * sizeof(SocialRecord);
    if (len < expected) return false;
    records.resize(hdr.count);
    if (hdr.count > 0) {
        std::memcpy(records.data(), data + sizeof(SOCHeader),
                    hdr.count * sizeof(SocialRecord));
    }
    return true;
}

// ============================================================================
// Filters
// ============================================================================

inline std::vector<SocialRecord> filterByPlatform(
    const std::vector<SocialRecord>& records, Platform p) {
    std::vector<SocialRecord> out;
    for (const auto& r : records)
        if (r.platform == static_cast<uint8_t>(p)) out.push_back(r);
    return out;
}

inline std::vector<SocialRecord> filterGeolocated(
    const std::vector<SocialRecord>& records) {
    std::vector<SocialRecord> out;
    for (const auto& r : records)
        if (!std::isnan(r.lat_deg) && !std::isnan(r.lon_deg)) out.push_back(r);
    return out;
}

inline std::vector<SocialRecord> filterByIntelFlag(
    const std::vector<SocialRecord>& records, IntelFlag flag) {
    std::vector<SocialRecord> out;
    for (const auto& r : records)
        if (r.intel_flags & static_cast<uint8_t>(flag)) out.push_back(r);
    return out;
}

inline std::vector<SocialRecord> filterViral(
    const std::vector<SocialRecord>& records, uint32_t minViews = 10000) {
    std::vector<SocialRecord> out;
    for (const auto& r : records)
        if (r.views >= minViews) out.push_back(r);
    return out;
}

}  // namespace socmint

#endif  // SOCMINT_TYPES_H
