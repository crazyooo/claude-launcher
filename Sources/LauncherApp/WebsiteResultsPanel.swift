import SwiftUI

struct WebsiteResultsPanel: View {
    @ObservedObject var session: WebsiteResultsSession

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("网站检测结果").font(.system(size: 16, weight: .semibold))
                Spacer()
                if session.busy {
                    ProgressView().controlSize(.small)
                    Button("停止") { session.cancel() }.buttonStyle(.link)
                }
                Button(session.busy ? "正在读取…" : "读取两页结果") { session.refresh() }
                    .buttonStyle(DetectorActionStyle(primary: true))
                    .disabled(session.busy)
            }
            Text("在 App 内运行这两个网页的检测并读取结果，使用当前系统网络路径。与外部浏览器或 Claude 的走线可能不同。")
                .font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            ForEach(WebsiteResultSource.allCases) { source in
                sourceCard(source, reading: session.readings[source] ?? .init())
            }
            Text("以上是网站的观察与评分，不计入本机检测结论，也不证明账号、订阅或对话可用。")
                .font(.system(size: 11)).foregroundStyle(DetectorStyle.muted)
        }
        .padding(18)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private func sourceCard(_ source: WebsiteResultSource, reading: WebsiteReading) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(source.title).font(.system(size: 14, weight: .semibold))
                Text(reading.phase.rawValue).font(.system(size: 11))
                    .foregroundStyle(reading.phase == .partial || reading.phase == .unavailable ? DetectorStyle.amber : DetectorStyle.muted)
                Spacer()
                Button("打开原网页") { ProductDetectActions.open(source.url.absoluteString) }.buttonStyle(.link)
            }
            Text(source.scope).font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            if let snapshot = reading.snapshot {
                Text("采样：" + snapshot.observedAt.formatted(date: .numeric, time: .standard))
                    .font(.system(size: 11)).foregroundStyle(DetectorStyle.muted)
                ForEach(snapshot.fields) { field in
                    HStack(alignment: .top, spacing: 14) {
                        Text(field.label).frame(width: 150, alignment: .leading).foregroundStyle(DetectorStyle.muted)
                        Text(field.value ?? (reading.phase == .loading ? "等待网站结果…" : "未取得"))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .font(.system(size: 12))
                }
                .opacity(reading.phase == .stale ? 0.55 : 1)
            }
            Text(reading.message).font(.system(size: 11)).foregroundStyle(DetectorStyle.muted)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.canvas, in: RoundedRectangle(cornerRadius: 10))
    }
}
