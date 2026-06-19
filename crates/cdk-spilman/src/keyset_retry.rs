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

/// Whether the helper is preparing the first attempt or the post-refresh retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetRetryPhase {
    /// Initial attempt before any retry refresh.
    First,
    /// Single retry after a retryable keyset rejection and refresh.
    Retry,
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
        /// Attempt phase that failed.
        phase: KeysetRetryPhase,
        /// Selection error.
        error: P,
    },
    /// Preparing attempt data from the selected keyset failed.
    Prepare {
        /// Attempt phase that failed.
        phase: KeysetRetryPhase,
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
    Select: FnMut(KeysetRetryPhase) -> Result<K, P>,
    Prepare: FnMut(K, KeysetRetryPhase) -> Result<A, P>,
    Submit: FnMut(&A) -> Result<T, S>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> Result<(), P>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select(KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Select {
        phase: KeysetRetryPhase::First,
        error,
    })?;
    let attempt =
        prepare(keyset, KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Prepare {
            phase: KeysetRetryPhase::First,
            error,
        })?;

    match submit(&attempt) {
        Ok(value) => Ok(KeysetRetrySuccess {
            attempt,
            value,
            retried: false,
        }),
        Err(error) if should_retry(&error) => {
            cleanup(&attempt, &error).map_err(|error| KeysetRetryError::Cleanup { error })?;
            refresh().map_err(|error| KeysetRetryError::Refresh { error })?;
            let keyset =
                select(KeysetRetryPhase::Retry).map_err(|error| KeysetRetryError::Select {
                    phase: KeysetRetryPhase::Retry,
                    error,
                })?;
            let attempt = prepare(keyset, KeysetRetryPhase::Retry).map_err(|error| {
                KeysetRetryError::Prepare {
                    phase: KeysetRetryPhase::Retry,
                    error,
                }
            })?;
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
    Select: FnMut(KeysetRetryPhase) -> Result<K, P>,
    Prepare: FnMut(K, KeysetRetryPhase) -> Result<A, P>,
    Submit: FnMut(A) -> SubmitFuture,
    SubmitFuture: Future<Output = Result<T, S>>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> RefreshFuture,
    RefreshFuture: Future<Output = Result<(), P>>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select(KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Select {
        phase: KeysetRetryPhase::First,
        error,
    })?;
    let attempt =
        prepare(keyset, KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Prepare {
            phase: KeysetRetryPhase::First,
            error,
        })?;

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
            let keyset =
                select(KeysetRetryPhase::Retry).map_err(|error| KeysetRetryError::Select {
                    phase: KeysetRetryPhase::Retry,
                    error,
                })?;
            let attempt = prepare(keyset, KeysetRetryPhase::Retry).map_err(|error| {
                KeysetRetryError::Prepare {
                    phase: KeysetRetryPhase::Retry,
                    error,
                }
            })?;
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

    #[test]
    fn sync_helper_returns_first_success_without_refresh() {
        let mut refreshes = 0;
        let result = with_active_keyset_retry(
            Ok::<_, &'static str>,
            |phase, _| Ok::<_, &'static str>(phase),
            |attempt| Ok::<_, &'static str>(*attempt),
            |_| true,
            || {
                refreshes += 1;
                Ok::<_, &'static str>(())
            },
            |_, _| Ok::<_, &'static str>(()),
        )
        .unwrap();

        assert_eq!(result.value, KeysetRetryPhase::First);
        assert!(!result.retried);
        assert_eq!(refreshes, 0);
    }

    #[test]
    fn sync_helper_retries_once_after_retryable_error() {
        let mut submits = 0;
        let mut refreshes = 0;
        let result = with_active_keyset_retry(
            Ok::<_, &'static str>,
            |phase, _| Ok::<_, &'static str>(phase),
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

        assert_eq!(result.attempt, KeysetRetryPhase::Retry);
        assert_eq!(result.value, "ok");
        assert!(result.retried);
        assert_eq!(submits, 2);
        assert_eq!(refreshes, 1);
    }

    #[test]
    fn sync_helper_returns_non_retryable_submit_error() {
        let result = with_active_keyset_retry(
            Ok::<_, &'static str>,
            |phase, _| Ok::<_, &'static str>(phase),
            |_attempt| Err::<(), _>("fatal"),
            |error| *error == "retryable",
            || Ok::<_, &'static str>(()),
            |_, _| Ok::<_, &'static str>(()),
        );

        assert_eq!(
            result,
            Err(KeysetRetryError::Submit {
                attempt: KeysetRetryPhase::First,
                error: "fatal",
                retried: false,
            })
        );
    }

    #[tokio::test]
    async fn async_helper_reports_refresh_failure() {
        let result = with_active_keyset_retry_async(
            Ok::<_, &'static str>,
            |phase, _| Ok::<_, &'static str>(phase),
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
}
