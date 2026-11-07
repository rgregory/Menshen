import AppKit
import Carbon
import Testing
@testable import menshen_launch

@Suite struct LauncherDeliveryTests {
    @Test @MainActor func opensDuringStartupRemainQueued() throws {
        let launcher = try #require(LauncherDelegate([
            "original": "/Applications/Test.app", "config": "/tmp/test.json",
            "dataRoot": "/tmp/menshen-test", "logsRoot": "/tmp/menshen-test/logs"
        ]))
        let initial = URL(fileURLWithPath: "/tmp/first.txt")
        let later = URL(fileURLWithPath: "/tmp/second.txt")
        launcher.enqueue([initial])
        #expect(launcher.initialArguments() == [initial.path])
        launcher.enqueue([later])
        launcher.flushPending()
        #expect(launcher.pending == [later], "requests arriving before Runner launches must survive")
    }

    @Test func openEventsAddressOnlyTheSpawnedPID() throws {
        let file = URL(fileURLWithPath: "/tmp/a document.txt")
        let event = LauncherDelegate.openEvent(file, pid: 12345)
        #expect(event.eventClass == AEEventClass(kCoreEventClass))
        #expect(event.eventID == AEEventID(kAEOpenDocuments))
        let address = try #require(event.attributeDescriptor(forKeyword: AEKeyword(keyAddressAttr)))
        #expect(address.descriptorType == DescType(typeKernelProcessID))
        #expect(address.data == NSAppleEventDescriptor(processIdentifier: 12345).data)
        #expect(event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.atIndex(1)?.fileURLValue == file)

        let url = try #require(URL(string: "https://example.com/document"))
        let webEvent = LauncherDelegate.openEvent(url, pid: 12345)
        #expect(webEvent.eventClass == AEEventClass(kInternetEventClass))
        #expect(webEvent.eventID == AEEventID(kAEGetURL))
        #expect(webEvent.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue == url.absoluteString)
    }
}
