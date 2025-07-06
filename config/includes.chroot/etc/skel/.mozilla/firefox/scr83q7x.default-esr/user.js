/**
 * Securonis Hardened FireScorpion Browser - user.js
 * 
 * This file contains primary security and privacy hardening settings
 * for the browser. This is where most hardening settings should be placed.
 * 
 * These settings are inspired by Tor Browser and
 * optimized to create minimal issues in daily usage.
 */

// ===== Telemetry and Data Collection Protection =====
// Disable all telemetry and data collection features to maximize privacy

// Prevent data submission to Mozilla
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.pioneer-new-studies-available", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("beacon.enabled", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", "");

// Disable studies and experiments
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// Disable crash reporter
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// ===== Disable Mozilla and Third-Party Integrations =====
// Disable Pocket
user_pref("extensions.pocket.enabled", false);

// Disable Mozilla accounts
user_pref("identity.fxaccounts.enabled", false);

// Disable Firefox Sync
user_pref("services.sync.enabled", false);
user_pref("identity.sync.tokenserver.uri", "");

// Disable access to Firefox Sync server
user_pref("services.sync.serverURL", "");

// Disable form autofill and browser history suggestions
user_pref("browser.formfill.enable", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.heuristics.enabled", false);

// Disable password manager
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);

// Disable addon recommendations but allow updates
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
// Enable automatic extension updates
user_pref("app.update.auto", true);
user_pref("extensions.update.enabled", true);
user_pref("extensions.update.autoUpdateDefault", true);

// ===== HTTPS and TLS Hardening =====
// Force HTTPS-only mode for maximum security
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode.upgrade_local", true);
user_pref("dom.security.https_only_mode.onion", false);

// Disable TLS 1.0 and 1.1 (keep TLS 1.2 and 1.3 only)
user_pref("security.tls.version.min", 3);
user_pref("security.tls.version.max", 4);

// OCSP hardening - must staple
user_pref("security.ssl.enable_ocsp_must_staple", true);
user_pref("security.OCSP.require", true);

// Disable insecure passive content
user_pref("security.mixed_content.block_display_content", true);
user_pref("security.mixed_content.block_object_subrequest", true);

// Disable insecure downloads from secure sites
user_pref("dom.block_download_insecure", true);

// Disable TLS Session Tickets
user_pref("security.ssl.disable_session_identifiers", true);

// Strict TLS negotiations
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("security.ssl.require_safe_negotiation", true);

// ===== Privacy and Tracking Protection =====
// First-Party Isolation
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.firstparty.isolate.restrict_opener_access", true);

// Tracking Protection
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.donottrackheader.value", 1);

// Enhanced Tracking Protection (strict)
user_pref("browser.contentblocking.category", "strict");
user_pref("browser.contentblocking.features.strict", "tp,tpPrivate,cookieBehavior5,cookieBehaviorPBM5,cm,fp,stp");

// ===== Comprehensive Browser Fingerprinting Protections =====
user_pref("privacy.resistFingerprinting", true);                // Main fingerprinting resistance
user_pref("privacy.resistFingerprinting.letterboxing", true);   // Enable letterboxing
user_pref("privacy.fingerprintingProtection.enabled", true);    // Additional fingerprinting protection
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true); // Prevent fingerprinting via add-on detection
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", true); // Auto-decline canvas access
user_pref("privacy.resistFingerprinting.randomization.daily_reset", true); // Daily reset of randomization
user_pref("privacy.resistFingerprinting.randomization.enabled", true); // Enable randomization
user_pref("privacy.resistFingerprinting.randomDataOnCanvasExtract", true); // Randomize canvas extraction
user_pref("privacy.reduceTimerPrecision", true); // Reduce timer precision
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 1000); // Set microsecond precision
// Value 0 is set later in the file for better fingerprinting protection
user_pref("device.sensors.enabled", false);                     // Disable device sensors
user_pref("geo.enabled", false);                               // Disable geolocation
user_pref("webgl.disabled", true);                             // Disable WebGL

// Canvas fingerprint protection
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", true); // Auto-decline canvas access
user_pref("canvas.capturestream.enabled", false);                // Disable canvas capture stream

// ===== WebRTC Protection =====
// Keep WebRTC enabled but with maximum security
user_pref("media.peerconnection.enabled", true);                // Keep WebRTC but with protections
user_pref("media.peerconnection.ice.relay_only", true);        // Use only TURN servers for maximum privacy
user_pref("media.peerconnection.ice.default_address_only", true); // Use default route only
user_pref("media.peerconnection.ice.no_host", true);           // Disable host ICE candidates
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // Use proxy when available

// ===== Network Settings =====
// Prefetching settings modified for better performance
user_pref("network.dns.disablePrefetch", true);                // Disable DNS prefetching
user_pref("network.dns.disablePrefetchFromHTTPS", true);       // Disable DNS prefetching from HTTPS
user_pref("network.predictor.enabled", false);                  // Disable network prediction
user_pref("network.predictor.enable-prefetch", false);          // Disable prefetch
user_pref("network.prefetch-next", false);                      // Disable link prefetching
user_pref("network.http.speculative-parallel-limit", 0);        // Disable speculative connections
user_pref("browser.urlbar.speculativeConnect.enabled", false);  // Disable speculative connections from URL bar

// Disable DNS over HTTPS (preventing Cloudflare DNS)
user_pref("network.trr.mode", 5);                              // Disable DNS over HTTPS
user_pref("network.trr.uri", "");                              // Clear DoH URI
user_pref("network.trr.bootstrapAddress", "");                // Clear DoH bootstrap address
user_pref("network.trr.default_provider_uri", "");            // Clear DoH provider URI

// ===== Advanced Network Isolation =====
user_pref("privacy.partition.network_state", true);               // Network state partitioning
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage", true);  // Partition 3rd party storage
user_pref("privacy.partition.serviceWorkers", true);              // Service Worker isolation
user_pref("privacy.storagePrincipal.enabledForTrackers", true);   // Storage isolation for trackers

// ===== Cookie and Storage Improvements =====
user_pref("privacy.sanitize.sanitizeOnShutdown", true);           // Clean on shutdown
user_pref("privacy.clearOnShutdown.offlineApps", true);           // Clear offline application data
user_pref("privacy.clearOnShutdown.siteSettings", false);         // Preserve site settings (for usability)
user_pref("privacy.sanitize.timeSpan", 0);                        // Clear all history

// ===== HTTP Security Headers =====
user_pref("network.http.referer.XOriginPolicy", 2);               // Limit referer information to same origin
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);       // Trim cross-origin referer header to domain
user_pref("network.http.referer.defaultPolicy.trackers", 1);      // Limit referer sending to trackers
user_pref("network.http.referer.defaultPolicy.trackers.pbmode", 1); // Limit referer to trackers in private mode

// ===== WebRTC Additional Security =====
user_pref("media.peerconnection.ice.default_address_only", true);  // Use default IP only (reduce IP leakage)
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // Use proxy only when behind proxy

// ===== Hardware Information Leak Protection =====
user_pref("media.navigator.mediacapabilities.enabled", false);     // Hide media capabilities
user_pref("dom.gamepad.enabled", false);                          // Disable gamepad API
user_pref("media.mediasource.enabled", true);                     // Keep Media Source Extensions enabled (for video)
user_pref("dom.w3c_touch_events.enabled", 0);                     // Disable touch screen API

// ===== DOM Security Improvements =====
user_pref("dom.targetBlankNoOpener.enabled", true);               // Apply noopener for target=_blank
user_pref("dom.popup_allowed_events", "click dblclick");          // Only allow popups on click events
user_pref("dom.disable_window_move_resize", true);                // Prevent window size/position changes
user_pref("dom.allow_scripts_to_close_windows", false);           // Prevent scripts from closing windows

// ===== Cache and Storage Limitations =====
user_pref("browser.sessionstore.privacy_level", 2);               // Session storage privacy (maximum)
user_pref("browser.sessionstore.interval", 30000);                // Session save interval (seconds)
user_pref("browser.sessionhistory.max_entries", 10);              // Keep fewer page history entries
user_pref("browser.sessionhistory.max_total_viewers", 4);         // Number of cached pages

// ===== Security Improvements =====
user_pref("security.tls.version.fallback-limit", 4);              // TLS fallback limit: TLS 1.3
user_pref("security.cert_pinning.enforcement_level", 2);          // Certificate pinning mandatory
user_pref("security.pki.sha1_enforcement_level", 1);              // Don't allow SHA-1 certificates
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);            // Disable weak cipher suite
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);            // Disable weak cipher suite

// ===== Privacy Improvements =====
user_pref("browser.link.open_newwindow.restriction", 0);          // Restrict new window opening
user_pref("permissions.default.geo", 2);                          // Deny location sharing by default
user_pref("permissions.default.camera", 2);                       // Deny camera access by default
user_pref("permissions.default.microphone", 2);                   // Deny microphone access by default
user_pref("permissions.default.desktop-notification", 2);         // Deny notifications by default
user_pref("permissions.default.xr", 2);                           // Deny VR access by default

// ===== JavaScript Security Balanced Settings =====
// Note: JIT engines are enabled for better web performance
// Comment these out if you need maximum security but reduced performance
// user_pref("javascript.options.wasm_baselinejit", false);
// user_pref("javascript.options.ion", false);
// user_pref("javascript.options.asmjs", false);
// user_pref("javascript.options.baselinejit", false);

// Alternative safer approach with better performance
user_pref("javascript.options.jit.content", true);               // Keep content JIT enabled
user_pref("javascript.options.jit.chrome", false);               // Disable UI JIT (security improvement)
user_pref("javascript.options.wasm_caching", false);             // Disable WASM caching for security

// ===== Tor Browser-like Additional Settings =====
user_pref("network.captive-portal-service.enabled", false);       // Disable captive portal detection
user_pref("network.connectivity-service.enabled", false);         // Disable connectivity checking
user_pref("network.dns.disableIPv6", true);                       // Disable IPv6 DNS
user_pref("network.IDN_show_punycode", true);                     // Show punycode (URL phishing protection)

// ===== Cache Improvements =====
user_pref("browser.cache.memory.capacity", 524288);             // Increase memory cache (512MB)
user_pref("browser.cache.memory.max_entry_size", 51200);        // Increase maximum cache entry size
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true); // Force media cache in RAM

// ===== Preferences - For Better Usability =====
user_pref("accessibility.blockautorefresh", false);                // Block auto-refresh
user_pref("browser.backspace_action", 2);                         // Don't use backspace as back navigation
user_pref("browser.tabs.warnOnClose", false);                     // Disable warning when closing multiple tabs
user_pref("browser.tabs.warnOnCloseOtherTabs", false);            // Disable warning when closing other tabs
user_pref("full-screen-api.warning.delay", 0);                    // Remove fullscreen warning delay
user_pref("full-screen-api.warning.timeout", 0);                  // Remove fullscreen warning timeout
user_pref("security.warn_about_mime_changes", false);            // Disable MIME type warnings
user_pref("security.warn_viewing_mixed", false);                 // Disable mixed content warnings
user_pref("security.dialog_enable_delay", 0);                    // Remove delay for security dialogs
user_pref("browser.xul.error_pages.enabled", true);              // Enable built-in error pages
user_pref("network.http.prompt-temp-redirect", false);           // Disable prompts for temporary redirects
user_pref("security.insecure_connection_text.enabled", false);   // Disable insecure connection warnings

// ===== Safe Browsing Privacy =====
// Disable Google Safe Browsing and phishing protection to prevent data sharing with Google
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.url", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");

// ===== Cookie and Storage Policies =====
// Default daily usage configuration - allows cookies with tracking protection
user_pref("network.cookie.cookieBehavior", 5);                    // Block all cross-site cookies
user_pref("network.cookie.lifetimePolicy", 2);                    // Accept cookies normally
user_pref("network.cookie.thirdparty.sessionOnly", true);         // Allow third-party cookies to persist
user_pref("network.cookie.thirdparty.nonsecureSessionOnly", true); // Still limit insecure third-party cookies to session

// Cookie partitioning settings
user_pref("privacy.partition.network_state", true);                // Partition network state
user_pref("privacy.partition.serviceWorkers.by_top_and_top", true); // Partition service workers
user_pref("privacy.partition.persistentStorageAccess.omitUserActivation", true); // Enhanced storage access partitioning

// ===== Cache Settings - Daily Mode =====
user_pref("browser.cache.disk.capacity", 1024000);                // Enable disk cache (1GB)
user_pref("browser.cache.disk.enable", true);                    // Enable disk cache
user_pref("browser.cache.disk.smart_size.enabled", true);        // Enable smart sizing of cache

// ===== DuckDuckGo Search Integration =====
// Set DuckDuckGo as default search engine
user_pref("browser.search.defaultenginename", "DuckDuckGo");
user_pref("browser.search.defaultenginename.US", "DuckDuckGo");
user_pref("browser.search.defaulturl", "https://duckduckgo.com/");
user_pref("keyword.URL", "https://duckduckgo.com/");

// DuckDuckGo URL Settings
user_pref("browser.newtab.url", "https://duckduckgo.com/");
user_pref("browser.search.hiddenOneOffs", "Google,Amazon.com,Bing,Yahoo,eBay,Twitter");

// ===== Theme Support Settings =====
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true); // default is false
user_pref("svg.context-properties.content.enabled", true);

// ===== Add-on Settings =====
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 15);
user_pref("extensions.installDistroAddons", true);
user_pref("xpinstall.signatures.required", false);
// Prevent extensions from opening their pages after installation
user_pref("extensions.ui.notifyHidden", true);
user_pref("extensions.webextensions.restrictedDomains", "accounts-static.cdn.mozilla.net,accounts.firefox.com,addons.cdn.mozilla.net,addons.mozilla.org,api.accounts.firefox.com,content.cdn.mozilla.net,discovery.addons.mozilla.org,install.mozilla.org,oauth.accounts.firefox.com,profile.accounts.firefox.com,support.mozilla.org,sync.services.mozilla.com");
user_pref("browser.startup.upgradeDialog.enabled", false);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.getAddons.cache.enabled", false);
// Allow extension update checks but disable recommendations
user_pref("extensions.getAddons.link.url", "https://addons.mozilla.org/%LOCALE%/firefox/");
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

// ===== Performance Optimizations =====
user_pref("network.http.max-connections", 900);                 // Increase max connections
user_pref("network.http.max-persistent-connections-per-server", 10); // Increase per-server connections
user_pref("network.http.max-urgent-start-excessive-connections-per-host", 5); // Allow more urgent connections
user_pref("network.http.pacing.requests.enabled", false);       // Disable request pacing
user_pref("security.ssl.enable_ocsp_stapling", true);          // Enable OCSP stapling

// Adjust some strict security settings for better performance
user_pref("security.ssl.require_safe_negotiation", false);     // Allow connections to older servers
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", false); // Don't mark older configurations as broken

// ===== Additional Privacy & Security Improvements =====
// Prevent accessibility services from accessing your browser
user_pref("accessibility.force_disabled", 1);

// Disable WebGL debugging and developer tools
user_pref("webgl.disable-debug-renderer-info", true);
user_pref("webgl.enable-debug-renderer-info", false);

// Additional fingerprinting protections
user_pref("privacy.resistFingerprinting.randomization.daily_reset", true);
user_pref("privacy.resistFingerprinting.randomization.enabled", true);
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", true);

// Enhanced referrer control
user_pref("network.http.referer.spoofSource", true);
user_pref("network.http.sendRefererHeader", 1);

// Service worker ayarları

// Disable clipboard events and notifications
user_pref("dom.event.clipboardevents.enabled", false);

// Enhanced media protection
user_pref("media.eme.enabled", false);

// Disable site reading installed plugins
user_pref("plugins.enumerable_names", "");

// Disable domain guessing
user_pref("browser.fixup.alternate.enabled", false);

// Disable search suggestions
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);

// Disable preloading of autocomplete URLs
user_pref("browser.urlbar.speculativeConnect.enabled", false);

// Disable saving of web page form and search history
user_pref("browser.formfill.enable", false);

// Disable face detection
user_pref("camera.control.face_detection.enabled", false);

// Disable reading battery status
user_pref("dom.battery.enabled", false);

// Disable keyboard fingerprinting
user_pref("dom.keyboardevent.code.enabled", false);

// Disable network information API
user_pref("dom.netinfo.enabled", false);

// Disable site reading installed themes
user_pref("devtools.chrome.enabled", false);

// Disable WebAssembly
user_pref("javascript.options.wasm", false);

// Additional Storage Protection
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.pagethumbnails.capturing_disabled", true);

// Disable Firefox account features
user_pref("identity.fxaccounts.enabled", false);
user_pref("identity.fxaccounts.commands.enabled", false);

// Enhanced SSL/TLS Security
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);

// Disable dormant tabs feature
user_pref("browser.tabs.unloadOnLowMemory", false);

// Additional tracking protection
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

// Telemetri ayarları dosyanın başında zaten tanımlanmış

// New tab and homepage settings
user_pref("browser.startup.page", 1);
user_pref("browser.startup.homepage", "https://duckduckgo.com/");
user_pref("browser.newtabpage.enabled", true);
user_pref("browser.newtab.preload", true);
user_pref("browser.newtabpage.activity-stream.default.sites", "https://duckduckgo.com/");
user_pref("browser.newtabpage.pinned", "[{\"url\":\"https://duckduckgo.com/\",\"label\":\"DuckDuckGo\"}]");
user_pref("browser.startup.firstrunSkipsHomepage", false);
user_pref("browser.newtabpage.activity-stream.prerender", true);
user_pref("browser.newtabpage.activity-stream.showSearch", true);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", true);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.topSitesRows", 1);
user_pref("browser.newtabpage.directory.source", "https://duckduckgo.com/");
user_pref("browser.newtabpage.directory.ping", "");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.startup.homepage_override.buildID", "");

// ===== Additional Hardening Without Breaking Usability =====

// Enhanced SSL/TLS Security
user_pref("security.tls.enable_0rtt_data", false);              // Disable 0-RTT to prevent replay attacks
user_pref("security.family_safety.mode", 0);                    // Disable Windows Family Safety cert store

// Enhanced Content Security
user_pref("security.mixed_content.block_active_content", true);  // Block active mixed content
user_pref("security.mixed_content.upgrade_display_content", true); // Upgrade passive mixed content
user_pref("security.mixed_content.block_display_content", true); // Block passive mixed content
user_pref("security.mixed_content.block_object_subrequest", true);
user_pref("security.csp.enable", true);                         // Enable CSP
user_pref("security.dialog_enable_delay", 2000);                // 2 second delay for security dialogs

// Additional Privacy Protections
user_pref("privacy.firstparty.isolate.restrict_opener_access", true); // Strict first party isolation
user_pref("privacy.resistFingerprinting.letterboxing", true);    // Enable letterboxing
user_pref("privacy.window.name.update.enabled", true);          // Clear window.name on domain change
user_pref("privacy.clearOnShutdown.cookies", true);            // Clear cookies for usability
user_pref("privacy.clearOnShutdown.formdata", true);           // Clear form data on shutdown
user_pref("privacy.clearOnShutdown.sessions", true);          // Clear session data for usability
user_pref("privacy.sanitize.sanitizeOnShutdown", true);        // Enable sanitize on shutdown

// Enhanced DOM Security
user_pref("dom.security.https_only_mode_send_http_background_request", false);
user_pref("dom.security.https_only_mode_error_page_user_suggestions", true);
user_pref("dom.event.contextmenu.enabled", false);              // Disable context menu hijacking
user_pref("dom.disable_window_move_resize", true);              // Prevent scripts from moving/resizing windows
user_pref("dom.popup_allowed_events", "click dblclick");        // Only allow popups on user clicks
user_pref("dom.disable_beforeunload", false);                    // Disable "Leave Page" popups
user_pref("dom.disable_open_during_load", true);                // Prevent automatic window opening
user_pref("dom.push.connection.enabled", false);                // Disable push notifications
user_pref("dom.webnotifications.enabled", false);               // Disable web notifications
// Service worker ayarları dosyanın başında zaten tanımlanmış

// Additional Network Security
user_pref("network.auth.subresource-http-auth-allow", 1);       // Strict HTTP authentication
// HTTP referrer ayarları
user_pref("network.http.referer.defaultPolicy", 2);             // Strict referer policy
user_pref("network.http.referer.defaultPolicy.pbmode", 2);      // Strict referer in private mode
user_pref("network.proxy.socks_remote_dns", true);              // Force DNS through SOCKS proxy
user_pref("network.security.esni.enabled", true);               // Enable Encrypted SNI if available

// WebRTC Hardening (while keeping it functional)
user_pref("media.peerconnection.ice.default_address_only", true); // Use default route only
user_pref("media.peerconnection.ice.no_host", true);             // Disable host ICE candidates
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // Use proxy when available
user_pref("media.peerconnection.ice.relay_only", false);         // Allow non-relay ICE for usability
user_pref("media.peerconnection.enabled", true);                 // Keep WebRTC enabled for usability
user_pref("media.navigator.video.enabled", false);               // Disable video unless needed
// Medya ayarları dosyanın başında zaten tanımlanmış

// Enhanced Extension Security
user_pref("extensions.webextensions.restrictedDomains", "accounts-static.cdn.mozilla.net,accounts.firefox.com,addons.cdn.mozilla.net,addons.mozilla.org,api.accounts.firefox.com,content.cdn.mozilla.net,discovery.addons.mozilla.org,install.mozilla.org,oauth.accounts.firefox.com,profile.accounts.firefox.com,support.mozilla.org,sync.services.mozilla.com");
user_pref("extensions.enabledScopes", 5);                        // Limit extension scope
user_pref("extensions.webextensions.protocol.remote", false);    // Disable remote protocol handlers
user_pref("extensions.webextensions.userScripts.enabled", false); // Disable user scripts

// Additional Fingerprinting Resistance
user_pref("webgl.disabled", false);                               // Disable WebGL
user_pref("canvas.capturestream.enabled", false);                // Disable canvas capture
user_pref("media.webspeech.synth.enabled", false);              // Disable speech synthesis
user_pref("media.webspeech.recognition.enable", false);         // Disable speech recognition
user_pref("device.sensors.enabled", false);                     // Disable device sensors
user_pref("browser.zoom.siteSpecific", false);                  // Disable per-site zoom
user_pref("dom.webaudio.enabled", false);                       // Disable Web Audio API

// Remove the risky empty restrictedDomains setting
user_pref("extensions.webextensions.restrictedDomains", "accounts-static.cdn.mozilla.net,accounts.firefox.com,addons.cdn.mozilla.net,addons.mozilla.org,api.accounts.firefox.com,content.cdn.mozilla.net,discovery.addons.mozilla.org,install.mozilla.org,oauth.accounts.firefox.com,profile.accounts.firefox.com,support.mozilla.org,sync.services.mozilla.com");

// Remove security dialog delay as it's annoying
user_pref("security.dialog_enable_delay", 0);                 // Remove delay for security dialogs

// ===== Privacy - Clear Data on Shutdown =====
// Consolidated clearOnShutdown settings 
user_pref("privacy.clearOnShutdown.cache", true);            // Clear cache
user_pref("privacy.clearOnShutdown.cookies", true);          // Clear cookies
user_pref("privacy.clearOnShutdown.downloads", true);        // Clear downloads
user_pref("privacy.clearOnShutdown.formdata", true);         // Clear form data
user_pref("privacy.clearOnShutdown.history", true);          // Clear history
user_pref("privacy.clearOnShutdown.offlineApps", true);      // Clear offline website data
user_pref("privacy.clearOnShutdown.sessions", false);        // Keep sessions for usability
user_pref("privacy.clearOnShutdown.siteSettings", false);    // Keep site settings
user_pref("privacy.sanitize.sanitizeOnShutdown", true);      // Enable sanitize on shutdown

// Session handling
user_pref("browser.sessionstore.privacy_level", 2);          // Store minimal session data
user_pref("browser.sessionstore.interval", 30000);           // Session save interval
user_pref("browser.sessionstore.max_tabs_undo", 0);          // Disable tab restore
user_pref("browser.sessionstore.resume_from_crash", true);   // Enable session restore after crash

// Cookie and Storage Restrictions
user_pref("network.cookie.lifetimePolicy", 2);               // Accept cookies for session only
user_pref("network.cookie.thirdparty.sessionOnly", true);    // Clear third-party cookies on session end
user_pref("browser.cache.disk.enable", false);               // Disable disk cache
user_pref("browser.cache.memory.enable", true);              // Keep memory cache for performance
user_pref("browser.cache.memory.capacity", 524288);          // 512MB memory cache

// Additional Tor/I2P compatibility settings
user_pref("network.proxy.socks_remote_dns", true);              // Force DNS through SOCKS proxy
user_pref("network.proxy.no_proxies_on", "");                   // Don't bypass proxy for any addresses
user_pref("network.security.ports.banned", "");                 // Don't restrict any ports
user_pref("network.dns.blockDotOnion", false);                 // Allow .onion domains
user_pref("dom.security.https_only_mode.onion", false);        // Don't force HTTPS for .onion addresses

// Enhanced Tor-style protections
user_pref("privacy.resistFingerprinting.randomDataOnCanvasExtract", true);
user_pref("privacy.resistFingerprinting.randomization.daily_reset", true);
user_pref("privacy.reduceTimerPrecision", true);
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 1000);

// Strengthen WebRTC protection
user_pref("media.peerconnection.ice.relay_only", true);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);

// Additional network protection
user_pref("network.protocol-handler.external.data", false);
user_pref("network.protocol-handler.external.guest", false);
user_pref("network.protocol-handler.external.javascript", false);

// Enhanced device fingerprinting protection
user_pref("dom.battery.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vibrator.enabled", false);
user_pref("dom.w3c_touch_events.enabled", 0);

// Font fingerprinting protection (comment out if breaks important sites)
user_pref("browser.display.use_document_fonts", 0);