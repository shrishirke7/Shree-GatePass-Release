import Foundation
import UserNotifications
import WebKit

final class AlertMonitor: NSObject, URLSessionDelegate {
    static let shared = AlertMonitor()
    private var timer: Timer?
    private var isForeground = false
    private var lastNotifRev = ""
    private var lastAlertId = ""
    private var session: URLSession!

    private override init() {
        super.init()
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 6
        cfg.timeoutIntervalForResource = 10
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    func setForeground(_ fg: Bool) {
        isForeground = fg
        if fg { startPolling() } else { pollOnce() }
    }

    func startPolling() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.timer?.invalidate()
            self.timer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
                self?.pollOnce()
            }
        }
    }

    func showLocalAlert(title: String, body: String, targetView: String) {
        let content = UNMutableNotificationContent()
        content.title = title.isEmpty ? "Shree GatePass" : title
        content.body = body.isEmpty ? "New Visitor or Material update" : body
        content.sound = .default
        content.userInfo = ["targetView": targetView.isEmpty ? "visitors" : targetView]
        let req = UNNotificationRequest(
            identifier: "gp-\(Int(Date().timeIntervalSince1970 * 1000))-\(UUID().uuidString.prefix(6))",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
    }

    func pollOnce(completion: (() -> Void)? = nil) {
        guard CertPinStore.isBgAlertsEnabled() else { completion?(); return }
        guard let origin = CertPinStore.buildOrigin(from: CertPinStore.getServerUrl()) else { completion?(); return }

        readCookieHeader(for: origin) { [weak self] cookieHeader in
            guard let self = self else { completion?(); return }
            self.fetchJson(urlString: "\(origin)/api/live-pulse", cookie: cookieHeader) { obj in
                guard let obj = obj else { completion?(); return }
                let notifRev = obj["notifRev"] as? String ?? ""
                let changed = !self.lastNotifRev.isEmpty && notifRev != self.lastNotifRev
                if !notifRev.isEmpty { self.lastNotifRev = notifRev }
                if changed && !self.isForeground {
                    self.checkLatestNotification(origin: origin, cookie: cookieHeader, completion: completion)
                } else {
                    completion?()
                }
            }
        }
    }

    private func readCookieHeader(for origin: String, completion: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            WKWebsiteDataStore.default().httpCookieStore.getAllCookies { cookies in
                guard let host = URL(string: origin)?.host?.lowercased() else { completion(nil); return }
                let matched = cookies.filter {
                    let dom = $0.domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    return host == dom || host.hasSuffix("." + dom)
                }
                if matched.isEmpty { completion(nil); return }
                completion(matched.map { "\($0.name)=\($0.value)" }.joined(separator: "; "))
            }
        }
    }

    private func fetchJson(urlString: String, cookie: String?, completion: @escaping ([String: Any]?) -> Void) {
        guard let url = URL(string: urlString) else { completion(nil); return }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("ShreeGatePass", forHTTPHeaderField: "X-Requested-With")
        if let cookie = cookie, !cookie.isEmpty { req.setValue(cookie, forHTTPHeaderField: "Cookie") }
        session.dataTask(with: req) { data, response, _ in
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(nil); return
            }
            completion(json)
        }.resume()
    }

    private func checkLatestNotification(origin: String, cookie: String?, completion: (() -> Void)?) {
        fetchJson(urlString: "\(origin)/api/live-alerts-feed", cookie: cookie) { [weak self] obj in
            guard let self = self, let obj = obj else { completion?(); return }
            let events = obj["events"] as? [[String: Any]] ?? []
            guard let latest = events.first else { completion?(); return }
            let id = latest["id"] as? String ?? ""
            guard !id.isEmpty, id != self.lastAlertId else { completion?(); return }
            self.lastAlertId = id
            if (latest["read"] as? Bool) == true { completion?(); return }

            let kind = latest["kind"] as? String ?? "visitor_entry"
            let title = latest["title"] as? String ?? "Shree GatePass Alert"
            let body = latest["body"] as? String ?? ""
            let targetView = latest["targetView"] as? String ?? "visitors"

            self.fetchJson(urlString: "\(origin)/api/notifications/sounds", cookie: cookie) { sObj in
                let prefs = sObj?["userPrefs"] as? [String: Any]
                let gcfg = sObj?["soundConfig"] as? [String: Any]
                let active = (prefs != nil && !(prefs?.isEmpty ?? true)) ? prefs : gcfg
                if let active = active {
                    if (active["enabled"] as? Bool) == false { completion?(); return }
                    if let cat = active[kind] as? [String: Any],
                       ((cat["enabled"] as? Bool) == false || (cat["silent"] as? Bool) == true) {
                        completion?(); return
                    }
                }
                self.showLocalAlert(title: title, body: body, targetView: targetView)
                completion?()
            }
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let host = challenge.protectionSpace.host
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            if CertPinStore.isCertPinned(host: host, fingerprint: fp) {
                completionHandler(.useCredential, URLCredential(trust: trust)); return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
