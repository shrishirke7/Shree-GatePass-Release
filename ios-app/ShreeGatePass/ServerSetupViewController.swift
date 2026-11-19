import UIKit

final class ServerSetupViewController: UIViewController, URLSessionDelegate {
    private let cardView = UIView()
    private let urlField = UITextField()
    private let bgAlertsSwitch = UISwitch()
    private let statusLabel = UILabel()
    private var testSession: URLSession!
    private var discoveredHost = ""
    private var discoveredFp = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.94, green: 0.96, blue: 0.94, alpha: 1)
        title = "GatePass Setup"

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 6
        testSession = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)

        setupUI()
        let saved = CertPinStore.getServerUrl()
        urlField.text = saved.isEmpty ? "https://gatepass.local:8859" : saved
        bgAlertsSwitch.isOn = CertPinStore.isBgAlertsEnabled()
    }

    private func setupUI() {
        cardView.backgroundColor = .white
        cardView.layer.cornerRadius = 18
        cardView.layer.borderWidth = 1
        cardView.layer.borderColor = UIColor(white: 0.88, alpha: 1).cgColor
        cardView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cardView)

        let titleLabel = UILabel()
        titleLabel.text = "Shree GatePass"
        titleLabel.font = .systemFont(ofSize: 22, weight: .heavy)
        titleLabel.textColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)

        let subLabel = UILabel()
        subLabel.text = "Connect your iPhone or iPad to Shree GatePass Server (supports LAN HTTPS certificates automatically)."
        subLabel.font = .systemFont(ofSize: 13)
        subLabel.textColor = UIColor(white: 0.40, alpha: 1)
        subLabel.numberOfLines = 0

        urlField.placeholder = "https://192.168.130.31:8859"
        urlField.borderStyle = .roundedRect
        urlField.autocapitalizationType = .none
        urlField.autocorrectionType = .no
        urlField.keyboardType = .URL

        let bgRow = UIStackView()
        bgRow.axis = .horizontal
        bgRow.alignment = .center
        bgRow.spacing = 12
        let bgLbl = UILabel()
        bgLbl.text = "Enable Visitor & Material Alerts"
        bgLbl.font = .systemFont(ofSize: 14, weight: .semibold)
        bgRow.addArrangedSubview(bgLbl)
        bgRow.addArrangedSubview(bgAlertsSwitch)

        let testBtn = UIButton(type: .system)
        testBtn.setTitle("Test Connection & SSL", for: .normal)
        testBtn.backgroundColor = UIColor(red: 0.92, green: 0.97, blue: 0.94, alpha: 1)
        testBtn.setTitleColor(UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1), for: .normal)
        testBtn.titleLabel?.font = .systemFont(ofSize: 14, weight: .bold)
        testBtn.layer.cornerRadius = 11
        testBtn.heightAnchor.constraint(equalToConstant: 44).isActive = true
        testBtn.addTarget(self, action: #selector(testPressed), for: .touchUpInside)

        let saveBtn = UIButton(type: .system)
        saveBtn.setTitle("Connect & Open Shree GatePass →", for: .normal)
        saveBtn.backgroundColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        saveBtn.setTitleColor(.white, for: .normal)
        saveBtn.titleLabel?.font = .systemFont(ofSize: 15, weight: .bold)
        saveBtn.layer.cornerRadius = 11
        saveBtn.heightAnchor.constraint(equalToConstant: 48).isActive = true
        saveBtn.addTarget(self, action: #selector(savePressed), for: .touchUpInside)

        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.numberOfLines = 0

        let stack = UIStackView(arrangedSubviews: [titleLabel, subLabel, urlField, bgRow, testBtn, saveBtn, statusLabel])
        stack.axis = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        cardView.addSubview(stack)

        NSLayoutConstraint.activate([
            cardView.centerYAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerYAnchor),
            cardView.centerXAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerXAnchor),
            cardView.leadingAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 18),
            cardView.trailingAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -18),
            cardView.widthAnchor.constraint(lessThanOrEqualToConstant: 480),
            stack.topAnchor.constraint(equalTo: cardView.topAnchor, constant: 24),
            stack.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -22),
            stack.bottomAnchor.constraint(equalTo: cardView.bottomAnchor, constant: -24)
        ])
    }

    private func normalizedUrl() -> String? {
        var raw = (urlField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return nil }
        if !raw.lowercased().hasPrefix("http://") && !raw.lowercased().hasPrefix("https://") {
            raw = raw.hasSuffix(":8858") ? ("http://" + raw) : ("https://" + raw)
        }
        while raw.hasSuffix("/") { raw.removeLast() }
        return URL(string: raw)?.host != nil ? raw : nil
    }

    @objc private func testPressed() {
        guard let urlStr = normalizedUrl(), let url = URL(string: urlStr + "/api/public/portal-options") else {
            statusLabel.text = "Enter a valid URL (e.g. https://192.168.130.31:8859)"
            statusLabel.textColor = .systemRed
            return
        }
        discoveredHost = ""
        discoveredFp = ""
        statusLabel.text = "Checking GatePass server..."
        testSession.dataTask(with: url) { [weak self] _, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let err = error {
                    self.statusLabel.text = "Error: \(err.localizedDescription)"
                    self.statusLabel.textColor = .systemRed
                    return
                }
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                self.statusLabel.text = !self.discoveredFp.isEmpty
                    ? "Connected (HTTP \(code)). Self-signed SSL pinned for \(self.discoveredHost)."
                    : "Server reachable (HTTP \(code))."
                self.statusLabel.textColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
            }
        }.resume()
    }

    @objc private func savePressed() {
        guard let urlStr = normalizedUrl() else {
            statusLabel.text = "Enter a valid GatePass server URL."
            statusLabel.textColor = .systemRed
            return
        }
        CertPinStore.saveServerUrl(urlStr)
        CertPinStore.setBgAlertsEnabled(bgAlertsSwitch.isOn)
        if !discoveredHost.isEmpty && !discoveredFp.isEmpty {
            CertPinStore.savePinnedCert(host: discoveredHost, fingerprint: discoveredFp)
        }
        if let nav = navigationController, nav.viewControllers.first !== self {
            nav.popViewController(animated: true)
            NotificationCenter.default.post(name: Notification.Name("GatePassServerUrlUpdated"), object: nil)
        } else if let window = view.window {
            window.rootViewController = MainViewController()
            UIView.transition(with: window, duration: 0.25, options: .transitionCrossDissolve, animations: nil)
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            let host = challenge.protectionSpace.host
            if !fp.isEmpty {
                discoveredHost = host
                discoveredFp = fp
                CertPinStore.savePinnedCert(host: host, fingerprint: fp)
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
