/**
 * Social Media Intelligence (SOCMINT) — Implementation
 * =======================================================
 *
 * Non-inline implementations for social media intelligence processing:
 *   1. Content hash computation (FNV-1a for dedup)
 *   2. Keyword / pattern matching for intel flag classification
 *   3. Basic sentiment scoring from keyword lists
 *   4. Mastodon/ActivityPub JSON parsing
 *   5. Telegram channel message parsing
 *   6. Platform-specific post URL builders
 *   7. Geolocation extraction from text (coordinate patterns)
 *   8. Engagement rate and virality scoring
 *
 * References:
 *   - X API v2: https://developer.twitter.com/en/docs/twitter-api
 *   - Mastodon API: https://docs.joinmastodon.org/api/
 *   - ActivityPub: https://www.w3.org/TR/activitypub/
 *   - Telegram Bot API: https://core.telegram.org/bots/api
 *   - Bellingcat OSINT methodology for SOCMINT
 */

#include "socmint/types.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <cctype>
#include <functional>

namespace socmint {

// ============================================================================
// Content Hashing (FNV-1a)
// ============================================================================

/// Compute FNV-1a hash for content deduplication.
/// Used to detect reposts, cross-platform duplicates, and content spreading.
uint64_t computeContentHash(const std::string& content) {
    uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
    for (char c : content) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL;  // FNV prime
    }
    return hash;
}

/// Compute hash ignoring whitespace and case (for fuzzy dedup)
uint64_t computeNormalizedHash(const std::string& content) {
    uint64_t hash = 14695981039346656037ULL;
    for (char c : content) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        hash ^= static_cast<uint8_t>(lower);
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ============================================================================
// Intel Flag Classification
// ============================================================================

/// Military/defense keyword patterns for automated flagging
static const std::vector<std::string> MILITARY_KEYWORDS = {
    "tank", "tanks", "artillery", "missile", "rockets", "convoy",
    "troops", "soldiers", "brigade", "battalion", "regiment",
    "airstrike", "bombing", "shelling", "drone strike",
    "SAM", "MANPADS", "HIMARS", "MLRS", "howitzer",
    "ammunition", "ammo depot", "military base",
    "fighter jet", "helicopter", "gunship",
    "warship", "frigate", "destroyer", "submarine",
    "radar", "air defense", "anti-aircraft",
};

static const std::vector<std::string> INFRASTRUCTURE_KEYWORDS = {
    "power plant", "nuclear plant", "oil refinery", "gas pipeline",
    "bridge destroyed", "bridge hit", "dam", "power grid",
    "water supply", "communications tower", "cell tower",
    "airport", "airfield", "railway", "rail bridge",
    "port", "harbor", "fuel depot", "transformer",
};

static const std::vector<std::string> MOVEMENT_KEYWORDS = {
    "moving toward", "advancing", "retreating", "withdrawal",
    "convoy spotted", "column of", "heading north", "heading south",
    "heading east", "heading west", "deployment", "mobilization",
    "crossing border", "troop movement", "reinforcements",
};

/// Check if text contains any keyword from a list (case-insensitive)
static bool containsKeyword(const std::string& text,
                             const std::vector<std::string>& keywords) {
    // Convert text to lowercase for matching
    std::string lower_text;
    lower_text.reserve(text.size());
    for (char c : text) {
        lower_text += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    for (const auto& kw : keywords) {
        if (lower_text.find(kw) != std::string::npos) {
            return true;
        }
    }
    return false;
}

/// Classify intel flags from post text content.
/// Returns a bitfield of IntelFlag values.
uint8_t classifyIntelFlags(const std::string& text,
                            double lat, double lon) {
    uint8_t flags = 0;

    // Geolocation
    if (!std::isnan(lat) && !std::isnan(lon)) {
        flags |= static_cast<uint8_t>(IntelFlag::GEOLOCATION);
    }

    // Check text for coordinate patterns
    // Common formats: 48.8566°N 2.3522°E, 48.8566, 2.3522
    // Also DMS: 48°51'24"N 2°21'8"E
    std::regex coord_pattern(R"(\d{1,3}\.\d{2,6}[°]?\s*[NSEW])");
    if (std::regex_search(text, coord_pattern)) {
        flags |= static_cast<uint8_t>(IntelFlag::GEOLOCATION);
    }

    // Keyword-based classification
    if (containsKeyword(text, MILITARY_KEYWORDS)) {
        flags |= static_cast<uint8_t>(IntelFlag::MILITARY);
    }
    if (containsKeyword(text, INFRASTRUCTURE_KEYWORDS)) {
        flags |= static_cast<uint8_t>(IntelFlag::INFRASTRUCTURE);
    }
    if (containsKeyword(text, MOVEMENT_KEYWORDS)) {
        flags |= static_cast<uint8_t>(IntelFlag::MOVEMENT);
    }

    return flags;
}

// ============================================================================
// Basic Sentiment Scoring
// ============================================================================

static const std::vector<std::string> POSITIVE_WORDS = {
    "good", "great", "excellent", "wonderful", "amazing", "fantastic",
    "happy", "love", "best", "win", "victory", "success", "peace",
    "beautiful", "thank", "thanks", "grateful", "proud", "hero",
};

static const std::vector<std::string> NEGATIVE_WORDS = {
    "bad", "terrible", "awful", "horrible", "worst", "hate",
    "angry", "sad", "death", "killed", "destroyed", "damaged",
    "failed", "crisis", "disaster", "threat", "attack", "war",
    "suffer", "pain", "tragic", "devastat", "catastroph",
};

static const std::vector<std::string> THREAT_WORDS = {
    "kill", "bomb", "attack", "destroy", "threaten", "assassin",
    "detonate", "explode", "execute", "eliminate", "eradicat",
};

/// Compute basic sentiment from text content.
/// Uses keyword-frequency approach (not ML-based — intentionally simple).
Sentiment classifySentiment(const std::string& text) {
    std::string lower;
    lower.reserve(text.size());
    for (char c : text) {
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    int positive = 0, negative = 0;
    bool has_threat = false;

    for (const auto& w : POSITIVE_WORDS) {
        size_t pos = 0;
        while ((pos = lower.find(w, pos)) != std::string::npos) {
            positive++;
            pos += w.size();
        }
    }
    for (const auto& w : NEGATIVE_WORDS) {
        size_t pos = 0;
        while ((pos = lower.find(w, pos)) != std::string::npos) {
            negative++;
            pos += w.size();
        }
    }
    for (const auto& w : THREAT_WORDS) {
        if (lower.find(w) != std::string::npos) {
            has_threat = true;
            break;
        }
    }

    if (has_threat) return Sentiment::THREAT;
    if (positive > negative + 1) return Sentiment::POSITIVE;
    if (negative > positive + 1) return Sentiment::NEGATIVE;
    if (positive == 0 && negative == 0) return Sentiment::UNKNOWN;
    return Sentiment::NEUTRAL;
}

// ============================================================================
// Mastodon / ActivityPub Post Parser
// ============================================================================

/// Parse a Mastodon API status JSON into a SocialRecord.
///
/// Mastodon API (GET /api/v1/statuses/:id) returns:
/// {
///   "id": "103270115826048975",
///   "created_at": "2019-12-08T03:48:33.901Z",
///   "content": "<p>HTML content</p>",
///   "account": {
///     "id": "1",
///     "acct": "user@instance.social",
///     "display_name": "User Name"
///   },
///   "favourites_count": 10,
///   "reblogs_count": 5,
///   "replies_count": 2,
///   "language": "en",
///   "tags": [{"name": "hashtag"}],
///   "media_attachments": [...]
/// }
bool parseMastodonStatus(const std::string& json, SocialRecord& record) {
    record = SocialRecord{};
    record.platform = static_cast<uint8_t>(Platform::MASTODON);
    record.lat_deg = NAN;
    record.lon_deg = NAN;

    // Simple JSON field extraction (no external JSON library dependency)
    auto extractStr = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos);
        if (pos == std::string::npos) return "";
        auto q1 = json.find('"', pos + 1);
        if (q1 == std::string::npos) return "";
        auto q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return "";
        return json.substr(q1 + 1, q2 - q1 - 1);
    };

    auto extractInt = [&](const std::string& key) -> int64_t {
        std::string search = "\"" + key + "\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos = json.find(':', pos);
        if (pos == std::string::npos) return 0;
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        if (pos >= json.size()) return 0;
        if (json[pos] == 'n') return 0;  // null
        try { return std::stoll(json.substr(pos)); }
        catch (...) { return 0; }
    };

    // Post ID
    std::string id = extractStr("id");
    std::strncpy(record.post_id, id.c_str(), sizeof(record.post_id) - 1);

    // Author handle (acct field)
    std::string acct = extractStr("acct");
    std::strncpy(record.author_handle, acct.c_str(), sizeof(record.author_handle) - 1);

    // Timestamp (ISO 8601)
    std::string created = extractStr("created_at");
    if (created.size() >= 19) {
        struct tm t{};
        t.tm_year = std::stoi(created.substr(0, 4)) - 1900;
        t.tm_mon  = std::stoi(created.substr(5, 2)) - 1;
        t.tm_mday = std::stoi(created.substr(8, 2));
        t.tm_hour = std::stoi(created.substr(11, 2));
        t.tm_min  = std::stoi(created.substr(14, 2));
        t.tm_sec  = std::stoi(created.substr(17, 2));
        record.epoch_s = static_cast<double>(timegm(&t));
    }

    // Language
    std::string lang = extractStr("language");
    std::strncpy(record.language, lang.c_str(), sizeof(record.language) - 1);

    // Engagement metrics
    record.likes = static_cast<uint32_t>(extractInt("favourites_count"));
    record.reposts = static_cast<uint32_t>(extractInt("reblogs_count"));
    record.replies = static_cast<uint32_t>(extractInt("replies_count"));

    // Content type
    record.content_type = static_cast<uint8_t>(ContentType::TEXT);

    // Content hash
    std::string content = extractStr("content");
    record.content_hash = computeContentHash(content);

    // Sentiment
    record.sentiment = static_cast<uint8_t>(classifySentiment(content));

    return !id.empty();
}

// ============================================================================
// Telegram Message Parser
// ============================================================================

/// Parse a Telegram Bot API message JSON into a SocialRecord.
///
/// Telegram Bot API message format:
/// {
///   "message_id": 12345,
///   "from": {"id": 123, "username": "user"},
///   "chat": {"id": -100123456, "title": "Channel"},
///   "date": 1710000000,
///   "text": "Message content"
/// }
bool parseTelegramMessage(const std::string& json, SocialRecord& record) {
    record = SocialRecord{};
    record.platform = static_cast<uint8_t>(Platform::TELEGRAM);
    record.lat_deg = NAN;
    record.lon_deg = NAN;

    auto extractStr = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos);
        if (pos == std::string::npos) return "";
        auto q1 = json.find('"', pos + 1);
        if (q1 == std::string::npos) return "";
        auto q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return "";
        return json.substr(q1 + 1, q2 - q1 - 1);
    };

    auto extractInt = [&](const std::string& key) -> int64_t {
        std::string search = "\"" + key + "\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos = json.find(':', pos);
        if (pos == std::string::npos) return 0;
        pos++;
        while (pos < json.size() && (json[pos] == ' ')) pos++;
        try { return std::stoll(json.substr(pos)); }
        catch (...) { return 0; }
    };

    // Message ID
    int64_t msg_id = extractInt("message_id");
    std::string id_str = std::to_string(msg_id);
    std::strncpy(record.post_id, id_str.c_str(), sizeof(record.post_id) - 1);

    // Author
    std::string username = extractStr("username");
    std::strncpy(record.author_handle, username.c_str(), sizeof(record.author_handle) - 1);

    // Timestamp (Unix epoch)
    record.epoch_s = static_cast<double>(extractInt("date"));

    // Text content
    std::string text = extractStr("text");
    record.content_hash = computeContentHash(text);
    record.content_type = static_cast<uint8_t>(ContentType::TEXT);

    // Check for location
    if (json.find("\"location\"") != std::string::npos) {
        // Try to extract lat/lon from location object
        auto pos = json.find("\"latitude\"");
        if (pos != std::string::npos) {
            pos = json.find(':', pos);
            if (pos != std::string::npos) {
                try { record.lat_deg = std::stod(json.substr(pos + 1)); }
                catch (...) {}
            }
        }
        pos = json.find("\"longitude\"");
        if (pos != std::string::npos) {
            pos = json.find(':', pos);
            if (pos != std::string::npos) {
                try { record.lon_deg = std::stod(json.substr(pos + 1)); }
                catch (...) {}
            }
        }
    }

    // Classify content
    record.intel_flags = classifyIntelFlags(text, record.lat_deg, record.lon_deg);
    record.sentiment = static_cast<uint8_t>(classifySentiment(text));

    return msg_id > 0;
}

// ============================================================================
// Platform URL Builders
// ============================================================================

/// Build a direct URL to a post on its platform.
std::string buildPostURL(const SocialRecord& record) {
    Platform p = static_cast<Platform>(record.platform);
    std::string post_id(record.post_id);
    std::string author(record.author_handle);

    switch (p) {
        case Platform::TWITTER:
            return "https://x.com/" + author + "/status/" + post_id;
        case Platform::MASTODON:
            // Mastodon URLs need instance; use author handle if it contains @
            if (author.find('@') != std::string::npos) {
                std::string instance = author.substr(author.find('@') + 1);
                std::string user = author.substr(0, author.find('@'));
                return "https://" + instance + "/@" + user + "/" + post_id;
            }
            return "mastodon://status/" + post_id;
        case Platform::REDDIT:
            return "https://reddit.com/comments/" + post_id;
        case Platform::TELEGRAM:
            return "https://t.me/c/" + post_id;
        case Platform::TIKTOK:
            return "https://www.tiktok.com/@" + author + "/video/" + post_id;
        case Platform::YOUTUBE:
            return "https://youtube.com/watch?v=" + post_id;
        case Platform::INSTAGRAM:
            return "https://instagram.com/p/" + post_id;
        default:
            return "";
    }
}

// ============================================================================
// Engagement & Virality
// ============================================================================

/// Compute engagement rate: (likes + reposts + replies) / views
/// Returns NAN if views == 0
double engagementRate(const SocialRecord& record) {
    if (record.views == 0) return NAN;
    double engagement = static_cast<double>(record.likes + record.reposts + record.replies);
    return engagement / static_cast<double>(record.views);
}

/// Compute a virality score (0-100) based on engagement velocity.
/// Considers: views, engagement rate, repost ratio
uint8_t viralityScore(const SocialRecord& record) {
    double score = 0;

    // View volume component (0-40 points, log scale)
    if (record.views > 0) {
        score += std::min(40.0, std::log10(static_cast<double>(record.views)) * 10.0);
    }

    // Engagement rate component (0-30 points)
    double er = engagementRate(record);
    if (!std::isnan(er)) {
        score += std::min(30.0, er * 1000.0);  // 3% ER = 30 points
    }

    // Repost ratio component (0-30 points)
    if (record.views > 0) {
        double repost_ratio = static_cast<double>(record.reposts) / record.views;
        score += std::min(30.0, repost_ratio * 3000.0);
    }

    return static_cast<uint8_t>(std::min(score, 100.0));
}

// ============================================================================
// Geolocation Extraction from Text
// ============================================================================

/// Extract decimal degree coordinates from text.
/// Supports formats:
///   - 48.8566, 2.3522
///   - 48.8566°N 2.3522°E
///   - N48.8566 E2.3522
/// Returns true if coordinates were found.
bool extractCoordinates(const std::string& text, double& lat, double& lon) {
    // Pattern: two decimal numbers that look like coordinates
    std::regex decimal_pattern(
        R"((-?\d{1,3}\.\d{2,8})\s*[°]?\s*([NS])?\s*[,\s]+\s*(-?\d{1,3}\.\d{2,8})\s*[°]?\s*([EW])?)");

    std::smatch match;
    if (std::regex_search(text, match, decimal_pattern)) {
        lat = std::stod(match[1].str());
        lon = std::stod(match[3].str());

        // Apply hemisphere signs
        if (match[2].matched && match[2].str() == "S") lat = -lat;
        if (match[4].matched && match[4].str() == "W") lon = -lon;

        // Validate ranges
        if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0) {
            return true;
        }
    }

    // Try N/E prefix format: N48.8566 E2.3522
    std::regex prefix_pattern(
        R"([NS]\s*(-?\d{1,3}\.\d{2,8})\s*[,\s]+\s*[EW]\s*(-?\d{1,3}\.\d{2,8}))");
    if (std::regex_search(text, match, prefix_pattern)) {
        lat = std::stod(match[1].str());
        lon = std::stod(match[2].str());

        size_t n_pos = text.find('N');
        size_t s_pos = text.find('S');
        if (s_pos != std::string::npos && (n_pos == std::string::npos || s_pos < n_pos))
            lat = -lat;

        size_t w_pos = text.find('W');
        if (w_pos != std::string::npos) lon = -lon;

        if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0)
            return true;
    }

    lat = NAN;
    lon = NAN;
    return false;
}

// ============================================================================
// Cross-platform Deduplication
// ============================================================================

/// Find duplicate posts across platforms using content hash.
/// Returns groups of indices that share the same hash.
std::vector<std::vector<size_t>> findCrossPlatformDuplicates(
    const std::vector<SocialRecord>& records) {

    // Group by content hash
    std::vector<std::pair<uint64_t, size_t>> hash_idx;
    for (size_t i = 0; i < records.size(); i++) {
        if (records[i].content_hash != 0) {
            hash_idx.push_back({records[i].content_hash, i});
        }
    }

    // Sort by hash
    std::sort(hash_idx.begin(), hash_idx.end());

    // Group consecutive equal hashes
    std::vector<std::vector<size_t>> groups;
    size_t i = 0;
    while (i < hash_idx.size()) {
        size_t j = i;
        while (j < hash_idx.size() && hash_idx[j].first == hash_idx[i].first) j++;

        if (j - i > 1) {
            // Multiple records with same hash = duplicates
            std::vector<size_t> group;
            for (size_t k = i; k < j; k++) {
                group.push_back(hash_idx[k].second);
            }
            groups.push_back(group);
        }
        i = j;
    }

    return groups;
}

}  // namespace socmint
