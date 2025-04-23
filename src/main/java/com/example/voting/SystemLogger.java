package com.example.voting;

import javafx.application.Platform;
import javafx.scene.control.TextArea;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * A simple static logger that outputs messages to a JavaFX TextArea
 * and optionally to the console. Ensures UI updates are on the FX thread.
 * 一个简单的静态记录器，将消息输出到 JavaFX TextArea，并可选地输出到控制台。
 * 确保 UI 更新在 FX 线程上。
 */
public class SystemLogger {

    private static TextArea logTextArea;
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static boolean consoleOutputEnabled = true; // Set to false to disable console logging 设置为 false 以禁用控制台日志记录

    /**
     * Sets the TextArea target for logging. Must be called from MainApp.
     * 设置日志记录的目标 TextArea。必须从 MainApp 调用。
     * @param area The TextArea UI component. TextArea UI 组件。
     */
    public static void setLogTextArea(TextArea area) {
        logTextArea = area;
    }

    /**
     * Enables or disables logging to System.out.
     * 启用或禁用对 System.out 的日志记录。
     * @param enabled true to enable console output, false to disable. true 表示启用控制台输出，false 表示禁用。
     */
    public static void setConsoleOutputEnabled(boolean enabled) {
        consoleOutputEnabled = enabled;
    }

    /**
     * Logs a message to the configured TextArea and/or console.
     * 将消息记录到配置的 TextArea 和/或控制台。
     * Prepends a timestamp to the message.
     * 在消息前添加时间戳。
     * @param message The message to log. 要记录的消息。
     */
    public static void log(String message) {
        String timestampedMessage = LocalTime.now().format(TIME_FORMATTER) + " - " + message;

        // Log to console if enabled
        // 如果启用，则记录到控制台
        if (consoleOutputEnabled) {
            System.out.println(timestampedMessage);
        }

        // Log to TextArea if set, ensuring it runs on the FX thread
        // 如果已设置，则记录到 TextArea，确保在 FX 线程上运行
        if (logTextArea != null) {
            Platform.runLater(() -> {
                logTextArea.appendText(timestampedMessage + "\n");
                // Optional: Auto-scroll to the bottom
                // 可选：自动滚动到底部
                // logTextArea.setScrollTop(Double.MAX_VALUE); // Can cause performance issues with lots of logs 可能导致大量日志的性能问题
                // logTextArea.positionCaret(logTextArea.getLength()); // Alternative scrolling 替代滚动方式
            });
        }
    }

    /**
     * Logs an error message. Typically includes more emphasis or goes to stderr.
     * 记录错误消息。通常包含更多强调或输出到 stderr。
     * @param message The error message to log. 要记录的错误消息。
     */
    public static void error(String message) {
        String timestampedMessage = LocalTime.now().format(TIME_FORMATTER) + " - ERROR - " + message;

        // Log error to console (stderr)
        // 将错误记录到控制台 (stderr)
        System.err.println(timestampedMessage);

        // Log error to TextArea (could add styling later if using RichTextFX)
        // 将错误记录到 TextArea（如果使用 RichTextFX，稍后可以添加样式）
        if (logTextArea != null) {
            Platform.runLater(() -> {
                logTextArea.appendText(timestampedMessage + "\n");
                // logTextArea.setScrollTop(Double.MAX_VALUE);
                // logTextArea.positionCaret(logTextArea.getLength());
            });
        }
    }
}