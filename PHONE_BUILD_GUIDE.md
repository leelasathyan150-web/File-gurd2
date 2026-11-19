# FILEGUARD FORENSICS — Phone-Only Cloud Build & Install Guide

Because this project was generated in an offline sandbox without the Android SDK, you can build the installable `FILEGUARD_FORENSICS.apk` **directly from your Android phone** in ~3 minutes using GitHub's free cloud build (`.github/workflows/build_apk.yml` is already included):

### Step 1: Upload to GitHub from Your Phone
1. Install or open the **GitHub** mobile app (or Chrome on `github.com`) and sign in.
2. Tap **+** → **New repository** → name it `FileGuardForensics` → tap **Create repository**.
3. Extract `FileGuardForensics_Project.zip` on your phone (using **Files by Google** or **ZArchiver**).
4. In GitHub on your browser (Desktop site mode if needed), tap **uploading an existing file**, upload the extracted files/folders (including `.github/workflows/build_apk.yml`), and tap **Commit changes**.

### Step 2: Download `FILEGUARD_FORENSICS.apk`
1. Open the **Actions** tab in your GitHub repository.
2. Wait ~2–3 minutes for **Build FILEGUARD_FORENSICS.apk** to finish with a green checkmark.
3. Tap the completed workflow run → scroll down to **Artifacts** → tap **FILEGUARD_FORENSICS-APK** to download the ZIP containing `FILEGUARD_FORENSICS.apk`.

### Step 3: Install on Android
1. Unzip the downloaded artifact in **Files by Google**.
2. Tap `FILEGUARD_FORENSICS.apk`.
3. If prompted, tap **Settings** → enable **Allow from this source** (Unknown Apps permission) for your file manager/browser.
4. Tap **Install** and open **FileGuard Forensics**.
