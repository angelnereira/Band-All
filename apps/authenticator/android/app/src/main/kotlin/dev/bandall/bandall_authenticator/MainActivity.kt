package dev.bandall.bandall_authenticator

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity

/**
 * The app's only activity, with `FLAG_SECURE` turned on (H7, item 6).
 *
 * An authenticator is a screen full of second factors, and it is read in
 * exactly the places screenshots are taken: queues, trains, a desk across the
 * room from someone else. Without this flag the window can be captured by
 * screenshots, by screen recording, and by the recents-screen thumbnail —
 * none of which the user has to be malicious, just distracted.
 *
 * The cost is real and deliberate: the user can no longer screenshot their own
 * codes, and the recents thumbnail is a blank card. For a second factor that
 * is the correct trade, and it matches what the UI already does by hiding codes
 * by default.
 *
 * It has to be set from native code because the flag belongs to the window, and
 * Flutter has no API for it.
 */
class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Before `super`, so the very first frame is already secure: a window
        // that was ever capturable leaves a thumbnail behind.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        super.onCreate(savedInstanceState)
    }
}