import Foundation
import Darwin
import RoutingCore

// Fixed service and private child entries; arbitrary commands are never accepted.
do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--host"] { try RouterSystemHost.run() }
    try RouterSystemCoreChild.run(arguments)
}
catch { Darwin._exit(78) } // Do not print credentials, configuration or private evidence.
