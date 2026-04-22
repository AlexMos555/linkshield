/**
 * Ribbon-button commands that run WITHOUT opening the task pane.
 *
 * Only one command today — `reportPhishing` — hit when the user clicks
 * the "Report phishing" button on the message-read surface.
 *
 * The handler must call `event.completed()` when finished; otherwise
 * Outlook will time the command out after ~2 minutes and show a spinner.
 */
"use strict";

const API_BASE = "https://api.cleanway.ai";

Office.onReady(() => {
  Office.actions.associate("reportPhishing", reportPhishing);
});

/**
 * Fire-and-forget report. Does NOT open the taskpane — this keeps the
 * flow "right-click → report → done" in Outlook's reading pane.
 *
 * @param {Office.AddinCommands.Event} event
 */
function reportPhishing(event) {
  const item = Office.context.mailbox.item;
  if (!item || !item.from) {
    finishWithNotification(
      event,
      "error",
      "Cleanway couldn't identify the sender for this message.",
    );
    return;
  }

  const payload = {
    source: "outlook",
    reason: "phishing",
    sender: item.from.emailAddress || "",
    subject: item.subject || "",
  };

  fetch(`${API_BASE}/api/v1/feedback/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
    .then((resp) => {
      if (!resp.ok) throw new Error(`${resp.status}`);
      finishWithNotification(
        event,
        "success",
        "Reported to Cleanway. Thanks for protecting others.",
      );
    })
    .catch((err) => {
      finishWithNotification(
        event,
        "error",
        `Report failed: ${err && err.message ? err.message : "network error"}`,
      );
    });
}

/**
 * Show an Outlook info-bar and complete the command. The notification key
 * is stable per message so repeat reports replace the existing indicator
 * rather than stacking.
 */
function finishWithNotification(event, kind, message) {
  const icon =
    kind === "success"
      ? Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage
      : Office.MailboxEnums.ItemNotificationMessageType.ErrorMessage;
  const item = Office.context.mailbox.item;
  if (item && item.notificationMessages && item.notificationMessages.replaceAsync) {
    item.notificationMessages.replaceAsync(
      "cleanway-report",
      {
        type: icon,
        message: message.slice(0, 150),
        icon: "icon16",
        persistent: false,
      },
      () => event.completed(),
    );
  } else {
    event.completed();
  }
}
