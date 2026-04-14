import React, { useEffect, useMemo, useState } from "react";
import { apiClient } from "../api/client.js";

export function PreviewPanel({ fileKey, onClose }) {
  const [preview, setPreview] = useState(null);
  const [comments, setComments] = useState([]);
  const [commentBody, setCommentBody] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!fileKey) return;
    setLoading(true);
    setError("");
    Promise.all([apiClient.preview(fileKey), apiClient.getComments(fileKey)])
      .then(([previewData, commentsData]) => {
        setPreview(previewData);
        setComments(commentsData.comments || []);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [fileKey]);

  const embedUrl = useMemo(() => {
    if (!preview?.url) return null;
    return preview.canDownload ? `${preview.url}?download=0` : preview.url;
  }, [preview]);

  if (!fileKey) return null;

  const downloadUrl = preview?.url ? `${preview.url}?download=1` : null;

  return (
    <div className="preview-backdrop" onClick={onClose}>
      <aside className="preview-panel" onClick={(event) => event.stopPropagation()}>
        <div className="panel-title-row">
          <div className="panel-title">Preview</div>
          <div className="preview-actions">
            {preview?.canDownload && downloadUrl ? (
              <a className="btn btn-sm btn-muted" href={downloadUrl} target="_blank" rel="noreferrer">
                Download
              </a>
            ) : null}
            <button type="button" className="btn btn-sm btn-muted" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
        <div className="muted preview-path">{fileKey}</div>

        <div className="preview-layout">
          <section className="preview-content">
            {loading ? <div className="empty-mini">Loading preview...</div> : null}
            {error ? <div className="error-banner">{error}</div> : null}

            {preview && !loading ? (
              <>
                {preview.previewType === "pdf" ? <iframe title="PDF Preview" src={embedUrl} className="preview-frame" /> : null}
                {preview.previewType === "image" ? <img alt="Preview" src={embedUrl} className="preview-image" /> : null}
                {preview.previewType === "video" ? (
                  <video controls className="preview-video">
                    <source src={embedUrl} type={preview.mimeType} />
                  </video>
                ) : null}
                {preview.textPreview ? <pre className="preview-text">{preview.textPreview}</pre> : null}
                {!preview.textPreview &&
                !["pdf", "image", "video"].includes(preview.previewType) ? (
                  <div className="empty-mini">No inline preview available for this file type.</div>
                ) : null}
              </>
            ) : null}
          </section>

          <section className="preview-comments">
            <div className="panel-title">Comments</div>
            <div className="comments-list">
              {comments.map((comment) => (
                <div key={comment.id} className="comment-row">
                  <div>
                    <strong>{comment.username}</strong>
                    <span className="muted"> · {new Date(comment.created_at).toLocaleString()}</span>
                  </div>
                  <div>{comment.body}</div>
                </div>
              ))}
              {!comments.length ? <div className="empty-mini">No comments yet.</div> : null}
            </div>

            <div className="comment-input-row">
              <textarea
                value={commentBody}
                onChange={(event) => setCommentBody(event.target.value)}
                placeholder="Add a comment"
              />
              <button
                type="button"
                className="btn btn-sm"
                onClick={async () => {
                  if (!commentBody.trim()) return;
                  try {
                    const payload = await apiClient.postComment(fileKey, commentBody.trim());
                    setComments((current) => [...current, payload.comment]);
                    setCommentBody("");
                  } catch (err) {
                    setError(err.message);
                  }
                }}
              >
                Comment
              </button>
            </div>
          </section>
        </div>
      </aside>
    </div>
  );
}

