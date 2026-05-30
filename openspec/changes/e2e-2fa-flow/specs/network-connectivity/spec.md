## ADDED Requirements

### Requirement: Phone connects to localhost backend via adb reverse
The development setup SHALL use `adb reverse tcp:8080 tcp:8080` to route the phone's `localhost:8080` to the laptop's `localhost:8080`. The app SHALL target `http://localhost:8080` as the server URL.

#### Scenario: adb reverse enables connectivity
- **WHEN** developer runs `adb reverse tcp:8080 tcp:8080` and starts the server on laptop port 8080
- **THEN** the Android app on the phone can reach the server at `http://localhost:8080`

### Requirement: App uses plain HTTP for development
The app SHALL use plain HTTP (not HTTPS) for the development server. The `AndroidManifest.xml` SHALL include `android:usesCleartextTraffic="true"` or a network security config allowing localhost cleartext.

#### Scenario: Cleartext traffic allowed to localhost
- **WHEN** app makes HTTP request to `http://localhost:8080`
- **THEN** Android does not block the request (cleartext allowed for localhost)

### Requirement: Server URL is configurable
The app SHALL have the server URL as a configurable constant (not hardcoded in multiple places) so it can be changed to ngrok or a real server URL.

#### Scenario: URL changed to ngrok
- **WHEN** developer changes `SERVER_URL` constant to an ngrok URL
- **THEN** all API calls use the new URL without any other code changes
