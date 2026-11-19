import UIKit
import WebKit
import AVFoundation

final class MainViewController: UIViewController,
                                WKNavigationDelegate,
                                WKUIDelegate,
                                WKScriptMessageHandler,
                                WKDownloadDelegate,
                                UIImagePickerControllerDelegate,
                                UINavigationControllerDelegate {

    private var webView: WKWebView!
    private var progressView = UIProgressView(progressViewStyle: .bar)
    private var errorOverlay = UIView()
    private var errorDetailLabel = UILabel()
    private var configuredHost = ""
    private var pendingCamCallbackFn = ""
    private var downloadTempUrl: URL?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.94, green: 0.96, blue: 0.94, alpha: 1)

        NotificationCenter.default.addObserver(self, selector: #selector(handleDeepLink(_:)), name: Notification.Name("GatePassDeepLinkNotification"), object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(handleServerUpdate), name: Notification.Name("GatePassServerUrlUpdated"), object: nil)

        setupWebView()
        setupProgressAndErrorUI()
        loadConfiguredServer()
    }

    private func setupWebView() {
        let userContent = WKUserContentController()
        userContent.add(self, name: "gatepassBridge")

        let bridgeScript = """
        (function(){
          if(window.ShreeIOS) return;
          const post = (action, payload) => {
            try{ window.webkit.messageHandlers.gatepassBridge.postMessage(Object.assign({action: action}, payload || {})); }catch(_){}
          };
          window.ShreeIOS = {
            notify: (title, body, targetView) => post('notify', {title: String(title||''), body: String(body||''), targetView: String(targetView||'visitors')}),
            openServerSettings: () => post('openServerSettings'),
            getAppVersion: () => '1.0.0',
            hasNativeCamera: () => true,
            openCamera: (callbackFn) => post('captureCameraPhoto', {facing: 'environment', callbackFn: String(callbackFn||'')}),
            captureCameraPhoto: (facing, callbackFn) => post('captureCameraPhoto', {facing: String(facing||'environment'), callbackFn: String(callbackFn||'')})
          };
        })();
        """
        userContent.addUserScript(WKUserScript(source: bridgeScript, injectionTime: .atDocumentStart, forMainFrameOnly: false))

        let config = WKWebViewConfiguration()
        config.userContentController = userContent
        config.allowsInlineMediaPlayback = true
        config.websiteDataStore = .default()

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        wv.uiDelegate = self
        wv.allowsBackForwardNavigationGestures = true
        wv.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(wv)
        self.webView = wv

        NSLayoutConstraint.activate([
            wv.topAnchor.constraint(equalTo: view.topAnchor),
            wv.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            wv.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            wv.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        wv.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
    }

    private func setupProgressAndErrorUI() {
        progressView.progressTintColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        progressView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(progressView)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            progressView.heightAnchor.constraint(equalToConstant: 2.5)
        ])

        errorOverlay.backgroundColor = view.backgroundColor
        errorOverlay.isHidden = true
        errorOverlay.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(errorOverlay)

        let title = UILabel()
        title.text = "Unable to connect to Shree GatePass Server"
        title.font = .systemFont(ofSize: 18, weight: .bold)
        title.textAlignment = .center

        errorDetailLabel.font = .systemFont(ofSize: 13)
        errorDetailLabel.textColor = .secondaryLabel
        errorDetailLabel.numberOfLines = 0
        errorDetailLabel.textAlignment = .center

        let retryBtn = UIButton(type: .system)
        retryBtn.setTitle("Retry Connection", for: .normal)
        retryBtn.backgroundColor = UIColor(red: 0.08, green: 0.48, blue: 0.33, alpha: 1)
        retryBtn.setTitleColor(.white, for: .normal)
        retryBtn.layer.cornerRadius = 10
        retryBtn.heightAnchor.constraint(equalToConstant: 44).isActive = true
        retryBtn.addTarget(self, action: #selector(retryLoad), for: .touchUpInside)

        let setupBtn = UIButton(type: .system)
        setupBtn.setTitle("Change Server URL", for: .normal)
        setupBtn.heightAnchor.constraint(equalToConstant: 40).isActive = true
        setupBtn.addTarget(self, action: #selector(openServerSettings), for: .touchUpInside)

        let stack = UIStackView(arrangedSubviews: [title, errorDetailLabel, retryBtn, setupBtn])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        errorOverlay.addSubview(stack)

        NSLayoutConstraint.activate([
            errorOverlay.topAnchor.constraint(equalTo: view.topAnchor),
            errorOverlay.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            errorOverlay.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            errorOverlay.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            stack.centerYAnchor.constraint(equalTo: errorOverlay.centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: errorOverlay.safeAreaLayoutGuide.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: errorOverlay.safeAreaLayoutGuide.trailingAnchor, constant: -28)
        ])
    }

    private func loadConfiguredServer() {
        guard let url = URL(string: CertPinStore.getServerUrl()) else {
            openServerSettings(); return
        }
        configuredHost = url.host ?? ""
        errorOverlay.isHidden = true
        webView.load(URLRequest(url: url))
    }

    @objc private func retryLoad() { loadConfiguredServer() }
    @objc private func handleServerUpdate() { loadConfiguredServer() }

    @objc private func openServerSettings() {
        let nav = UINavigationController(rootViewController: ServerSetupViewController())
        nav.modalPresentationStyle = .formSheet
        present(nav, animated: true)
    }

    @objc private func handleDeepLink(_ note: Notification) {
        let targetView = note.userInfo?["targetView"] as? String ?? ""
        guard !targetView.isEmpty else { return }
        let js = "if(typeof window.switchView==='function'){window.switchView(\(jsonLiteral(targetView)));}"
        webView.evaluateJavaScript(js, completionHandler: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == #keyPath(WKWebView.estimatedProgress) {
            let p = Float(webView.estimatedProgress)
            progressView.isHidden = p >= 1.0
            progressView.setProgress(p, animated: true)
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "gatepassBridge", let dict = message.body as? [String: Any],
              let action = dict["action"] as? String else { return }
        switch action {
        case "notify":
            AlertMonitor.shared.showLocalAlert(
                title: dict["title"] as? String ?? "Shree GatePass",
                body: dict["body"] as? String ?? "",
                targetView: dict["targetView"] as? String ?? "visitors"
            )
        case "openServerSettings":
            openServerSettings()
        case "captureCameraPhoto":
            startNativeCamera(facing: dict["facing"] as? String ?? "environment", callbackFn: dict["callbackFn"] as? String ?? "")
        default:
            break
        }
    }

    private func startNativeCamera(facing: String, callbackFn: String) {
        pendingCamCallbackFn = callbackFn
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        if status == .notDetermined {
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async { if granted { self?.presentPicker(facing: facing) } }
            }
            return
        }
        presentPicker(facing: facing)
    }

    private func presentPicker(facing: String) {
        let picker = UIImagePickerController()
        picker.delegate = self
        if UIImagePickerController.isSourceTypeAvailable(.camera) {
            picker.sourceType = .camera
            picker.cameraDevice = (facing == "user" && UIImagePickerController.isCameraDeviceAvailable(.front)) ? .front : .rear
        } else {
            picker.sourceType = .photoLibrary
        }
        if UIDevice.current.userInterfaceIdiom == .pad { picker.modalPresentationStyle = .formSheet }
        present(picker, animated: true)
    }

    func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
        picker.dismiss(animated: true)
        pendingCamCallbackFn = ""
    }

    func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
        picker.dismiss(animated: true)
        let cbFn = pendingCamCallbackFn
        pendingCamCallbackFn = ""
        guard !cbFn.isEmpty, let img = (info[.originalImage] as? UIImage)?.normalizedUp() else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let maxSide: CGFloat = 1400
            let scale = min(1.0, maxSide / max(img.size.width, img.size.height))
            let targetSize = CGSize(width: round(img.size.width * scale), height: round(img.size.height * scale))
            let rendered = UIGraphicsImageRenderer(size: targetSize).image { _ in img.draw(in: CGRect(origin: .zero, size: targetSize)) }
            guard let jpeg = rendered.jpegData(compressionQuality: 0.85) else { return }
            let dataUrl = "data:image/jpeg;base64," + jpeg.base64EncodedString()
            DispatchQueue.main.async {
                let fnLit = self?.jsonLiteral(cbFn) ?? "''"
                let urlLit = self?.jsonLiteral(dataUrl) ?? "''"
                self?.webView.evaluateJavaScript("if(typeof window[\(fnLit)]==='function'){window[\(fnLit)](\(urlLit));}", completionHandler: nil)
            }
        }
    }

    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            let host = challenge.protectionSpace.host
            let fp = CertPinStore.sha256Fingerprint(trust: trust)
            if !fp.isEmpty && CertPinStore.isCertPinned(host: host, fingerprint: fp) {
                completionHandler(.useCredential, URLCredential(trust: trust)); return
            }
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { completionHandler(.cancelAuthenticationChallenge, nil); return }
                let alert = UIAlertController(
                    title: "Trust GatePass Server?",
                    message: "Host: \(host)\nSHA-256: \(fp)\n\nTrust & pin this local SSL certificate?",
                    preferredStyle: .alert
                )
                alert.addAction(UIAlertAction(title: "Trust & Connect", style: .default) { _ in
                    if !fp.isEmpty { CertPinStore.savePinnedCert(host: host, fingerprint: fp) }
                    completionHandler(.useCredential, URLCredential(trust: trust))
                })
                alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                    completionHandler(.cancelAuthenticationChallenge, nil)
                })
                self.present(alert, animated: true)
            }
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if let http = navigationResponse.response as? HTTPURLResponse,
           (http.allHeaderFields["Content-Disposition"] as? String ?? "").lowercased().contains("attachment") {
            decisionHandler(.download); return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) { download.delegate = self }
    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(suggestedFilename)
        try? FileManager.default.removeItem(at: dest)
        downloadTempUrl = dest
        completionHandler(dest)
    }
    func downloadDidFinish(_ download: WKDownload) {
        guard let url = downloadTempUrl else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let vc = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            if let pop = vc.popoverPresentationController {
                pop.sourceView = self.view
                pop.sourceRect = CGRect(x: self.view.bounds.midX, y: self.view.bounds.midY, width: 1, height: 1)
            }
            self.present(vc, animated: true)
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        errorDetailLabel.text = "Server: \(CertPinStore.getServerUrl())\nError: \(error.localizedDescription)"
        errorOverlay.isHidden = false
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { errorOverlay.isHidden = true }

    private func jsonLiteral(_ value: String) -> String {
        if let data = try? JSONSerialization.data(withJSONObject: [value]),
           let str = String(data: data, encoding: .utf8), str.count >= 2 {
            return String(str.dropFirst().dropLast())
        }
        return "\"\""
    }
}

private extension UIImage {
    func normalizedUp() -> UIImage {
        if imageOrientation == .up { return self }
        return UIGraphicsImageRenderer(size: size).image { _ in draw(in: CGRect(origin: .zero, size: size)) }
    }
}
