//! Generic one-shot keyset refresh/retry helpers.

use std::future::Future;

/// Active output keyset selected for a mint/unit attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedOutputKeyset {
    /// Keyset id selected for output proofs.
    pub id: String,
    /// Serialized keyset info JSON for the selected keyset.
    pub info_json: String,
}

/// A selection result that exposes the active output keyset chosen for retry comparison.
pub trait ActiveKeysetSelection {
    /// Selected output keyset used to build the attempted swap.
    fn selected_output_keyset(&self) -> &SelectedOutputKeyset;
}

impl ActiveKeysetSelection for SelectedOutputKeyset {
    fn selected_output_keyset(&self) -> &SelectedOutputKeyset {
        self
    }
}

/// Successful result from a keyset-refresh retry helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetRetrySuccess<A, T> {
    /// Attempt data used for the successful submission.
    pub attempt: A,
    /// Successful submission value.
    pub value: T,
    /// Whether the retry branch was used.
    pub retried: bool,
}

/// Failure from a keyset-refresh retry helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetRetryError<A, P, S> {
    /// Selecting an active output keyset failed.
    Select {
        /// Selection error.
        error: P,
    },
    /// Preparing attempt data from the selected keyset failed.
    Prepare {
        /// Preparation error.
        error: P,
    },
    /// Refreshing keysets after a retryable rejection failed.
    Refresh {
        /// Refresh error.
        error: P,
    },
    /// Cleaning up first-attempt state before retry failed.
    Cleanup {
        /// Cleanup error.
        error: P,
    },
    /// Submission failed.
    Submit {
        /// Attempt data used for the failed submission.
        attempt: A,
        /// Submission error.
        error: S,
        /// Whether this was the retry submission.
        retried: bool,
    },
    /// A retryable submission failed, but refreshed selection chose the same output keyset.
    RetryKeysetUnchanged {
        /// Attempt data used for the first failed submission.
        attempt: A,
        /// First submission error.
        error: S,
        /// Unchanged selected keyset id.
        keyset_id: String,
    },
}

/// Run one synchronous attempt, refresh keysets on retryable rejection, then retry once.
pub fn with_active_keyset_retry<
    K,
    A,
    T,
    P,
    S,
    Select,
    Prepare,
    Submit,
    ShouldRetry,
    Refresh,
    Cleanup,
>(
    mut select: Select,
    mut prepare: Prepare,
    mut submit: Submit,
    mut should_retry: ShouldRetry,
    mut refresh: Refresh,
    mut cleanup: Cleanup,
) -> Result<KeysetRetrySuccess<A, T>, KeysetRetryError<A, P, S>>
where
    K: ActiveKeysetSelection,
    Select: FnMut() -> Result<K, P>,
    Prepare: FnMut(K) -> Result<A, P>,
    Submit: FnMut(&A) -> Result<T, S>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> Result<(), P>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select().map_err(|error| KeysetRetryError::Select { error })?;
    let keyset_id = keyset.selected_output_keyset().id.clone();
    let attempt = prepare(keyset).map_err(|error| KeysetRetryError::Prepare { error })?;

    match submit(&attempt) {
        Ok(value) => Ok(KeysetRetrySuccess {
            attempt,
            value,
            retried: false,
        }),
        Err(error) if should_retry(&error) => {
            cleanup(&attempt, &error).map_err(|error| KeysetRetryError::Cleanup { error })?;
            refresh().map_err(|error| KeysetRetryError::Refresh { error })?;
            let retry_keyset = select().map_err(|error| KeysetRetryError::Select { error })?;
            let retry_keyset_id = retry_keyset.selected_output_keyset().id.clone();
            if retry_keyset_id == keyset_id {
                return Err(KeysetRetryError::RetryKeysetUnchanged {
                    attempt,
                    error,
                    keyset_id,
                });
            }
            let attempt =
                prepare(retry_keyset).map_err(|error| KeysetRetryError::Prepare { error })?;
            match submit(&attempt) {
                Ok(value) => Ok(KeysetRetrySuccess {
                    attempt,
                    value,
                    retried: true,
                }),
                Err(error) => Err(KeysetRetryError::Submit {
                    attempt,
                    error,
                    retried: true,
                }),
            }
        }
        Err(error) => Err(KeysetRetryError::Submit {
            attempt,
            error,
            retried: false,
        }),
    }
}

/// Run one asynchronous attempt, refresh keysets on retryable rejection, then retry once.
pub async fn with_active_keyset_retry_async<
    K,
    A,
    T,
    P,
    S,
    Select,
    Prepare,
    Submit,
    SubmitFuture,
    ShouldRetry,
    Refresh,
    RefreshFuture,
    Cleanup,
>(
    mut select: Select,
    mut prepare: Prepare,
    mut submit: Submit,
    mut should_retry: ShouldRetry,
    mut refresh: Refresh,
    mut cleanup: Cleanup,
) -> Result<KeysetRetrySuccess<A, T>, KeysetRetryError<A, P, S>>
where
    A: Clone,
    K: ActiveKeysetSelection,
    Select: FnMut() -> Result<K, P>,
    Prepare: FnMut(K) -> Result<A, P>,
    Submit: FnMut(A) -> SubmitFuture,
    SubmitFuture: Future<Output = Result<T, S>>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> RefreshFuture,
    RefreshFuture: Future<Output = Result<(), P>>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select().map_err(|error| KeysetRetryError::Select { error })?;
    let keyset_id = keyset.selected_output_keyset().id.clone();
    let attempt = prepare(keyset).map_err(|error| KeysetRetryError::Prepare { error })?;

    match submit(attempt.clone()).await {
        Ok(value) => Ok(KeysetRetrySuccess {
            attempt,
            value,
            retried: false,
        }),
        Err(error) if should_retry(&error) => {
            cleanup(&attempt, &error).map_err(|error| KeysetRetryError::Cleanup { error })?;
            refresh()
                .await
                .map_err(|error| KeysetRetryError::Refresh { error })?;
            let retry_keyset = select().map_err(|error| KeysetRetryError::Select { error })?;
            let retry_keyset_id = retry_keyset.selected_output_keyset().id.clone();
            if retry_keyset_id == keyset_id {
                return Err(KeysetRetryError::RetryKeysetUnchanged {
                    attempt,
                    error,
                    keyset_id,
                });
            }
            let attempt =
                prepare(retry_keyset).map_err(|error| KeysetRetryError::Prepare { error })?;
            match submit(attempt.clone()).await {
                Ok(value) => Ok(KeysetRetrySuccess {
                    attempt,
                    value,
                    retried: true,
                }),
                Err(error) => Err(KeysetRetryError::Submit {
                    attempt,
                    error,
                    retried: true,
                }),
            }
        }
        Err(error) => Err(KeysetRetryError::Submit {
            attempt,
            error,
            retried: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset(id: &str) -> SelectedOutputKeyset {
        SelectedOutputKeyset {
            id: id.to_string(),
            info_json: format!("{{\"id\":\"{id}\"}}"),
        }
    }

    #[test]
    fn sync_helper_returns_first_success_without_refresh() {
        let mut refreshes = 0;
        let result = with_active_keyset_retry(
            || Ok::<_, &'static str>(keyset("a")),
            |keyset| Ok::<_, &'static str>(keyset.id),
            |attempt| Ok::<_, &'static str>(attempt.clone()),
            |_| true,
            || {
                refreshes += 1;
                Ok::<_, &'static str>(())
            },
            |_, _| Ok::<_, &'static str>(()),
        )
        .unwrap();

        assert_eq!(result.value, "a");
        assert!(!result.retried);
        assert_eq!(refreshes, 0);
    }

    #[test]
    fn sync_helper_retries_once_after_changed_keyset() {
        let mut selects = 0;
        let mut submits = 0;
        let mut refreshes = 0;
        let result = with_active_keyset_retry(
            || {
                selects += 1;
                Ok::<_, &'static str>(keyset(if selects == 1 { "a" } else { "b" }))
            },
            |keyset| Ok::<_, &'static str>(keyset.id),
            |_attempt| {
                submits += 1;
                if submits == 1 {
                    Err("retryable")
                } else {
                    Ok("ok")
                }
            },
            |error| *error == "retryable",
            || {
                refreshes += 1;
                Ok::<_, &'static str>(())
            },
            |_, _| Ok::<_, &'static str>(()),
        )
        .unwrap();

        assert_eq!(result.attempt, "b");
        assert_eq!(result.value, "ok");
        assert!(result.retried);
        assert_eq!(selects, 2);
        assert_eq!(submits, 2);
        assert_eq!(refreshes, 1);
    }

    #[test]
    fn sync_helper_skips_retry_when_keyset_unchanged() {
        let mut selects = 0;
        let mut submits = 0;
        let result = with_active_keyset_retry(
            || {
                selects += 1;
                Ok::<_, &'static str>(keyset("a"))
            },
            |keyset| Ok::<_, &'static str>(keyset.id),
            |_attempt| {
                submits += 1;
                Err::<(), _>("retryable")
            },
            |error| *error == "retryable",
            || Ok::<_, &'static str>(()),
            |_, _| Ok::<_, &'static str>(()),
        );

        assert_eq!(
            result,
            Err(KeysetRetryError::RetryKeysetUnchanged {
                attempt: "a".to_string(),
                error: "retryable",
                keyset_id: "a".to_string(),
            })
        );
        assert_eq!(selects, 2);
        assert_eq!(submits, 1);
    }

    #[test]
    fn sync_helper_returns_non_retryable_submit_error() {
        let result = with_active_keyset_retry(
            || Ok::<_, &'static str>(keyset("a")),
            |keyset| Ok::<_, &'static str>(keyset.id),
            |_attempt| Err::<(), _>("fatal"),
            |error| *error == "retryable",
            || Ok::<_, &'static str>(()),
            |_, _| Ok::<_, &'static str>(()),
        );

        assert_eq!(
            result,
            Err(KeysetRetryError::Submit {
                attempt: "a".to_string(),
                error: "fatal",
                retried: false,
            })
        );
    }

    #[tokio::test]
    async fn async_helper_reports_refresh_failure() {
        let result = with_active_keyset_retry_async(
            || Ok::<_, &'static str>(keyset("a")),
            |keyset| Ok::<_, &'static str>(keyset.id),
            |_attempt| async { Err::<(), _>("retryable") },
            |error| *error == "retryable",
            || async { Err::<(), _>("refresh failed") },
            |_, _| Ok::<_, &'static str>(()),
        )
        .await;

        assert_eq!(
            result,
            Err(KeysetRetryError::Refresh {
                error: "refresh failed"
            })
        );
    }

    #[tokio::test]
    async fn async_helper_skips_retry_when_keyset_unchanged() {
        let mut submits = 0;
        let result = with_active_keyset_retry_async(
            || Ok::<_, &'static str>(keyset("a")),
            |keyset| Ok::<_, &'static str>(keyset.id),
            |_attempt| {
                submits += 1;
                async { Err::<(), _>("retryable") }
            },
            |error| *error == "retryable",
            || async { Ok::<_, &'static str>(()) },
            |_, _| Ok::<_, &'static str>(()),
        )
        .await;

        assert_eq!(
            result,
            Err(KeysetRetryError::RetryKeysetUnchanged {
                attempt: "a".to_string(),
                error: "retryable",
                keyset_id: "a".to_string(),
            })
        );
        assert_eq!(submits, 1);
    }
}
