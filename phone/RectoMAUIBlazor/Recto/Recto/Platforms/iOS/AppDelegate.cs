using Foundation;
using ObjCRuntime;
using Recto.Platforms.iOSImpl;
using UIKit;

namespace Recto;

[Register("AppDelegate")]
public class AppDelegate : MauiUIApplicationDelegate
{
    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

    /// <summary>
    /// Called by iOS after a successful APNs registration. Forwards the
    /// device token to <see cref="IosApnsPushTokenService"/> which resolves
    /// any pending fetch.
    /// <para>
    /// Wired via <c>[Export]</c> selector rather than <c>override</c>
    /// because <see cref="MauiUIApplicationDelegate"/>'s base class doesn't
    /// expose this as a virtual method in modern .NET MAUI iOS bindings;
    /// the Objective-C runtime dispatches by selector regardless of CLR
    /// inheritance.
    /// </para>
    /// </summary>
    [Export("application:didRegisterForRemoteNotificationsWithDeviceToken:")]
    public void RegisteredForRemoteNotifications(UIApplication application, NSData deviceToken)
    {
        IosApnsPushTokenService.OnRegisteredForRemoteNotifications(deviceToken);
    }

    /// <summary>
    /// Called by iOS when APNs registration fails (typically: missing push
    /// entitlement on the provisioning profile, or the bundle ID isn't
    /// configured for push in the Apple Developer Program).
    /// </summary>
    [Export("application:didFailToRegisterForRemoteNotificationsWithError:")]
    public void FailedToRegisterForRemoteNotifications(UIApplication application, NSError error)
    {
        IosApnsPushTokenService.OnFailedToRegisterForRemoteNotifications(error);
    }
}
