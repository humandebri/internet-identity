<script lang="ts">
  import { channelStore } from "$lib/stores/channelStore";
  import { t } from "$lib/stores/locale.store";
  import {
    type Channel,
    type ChannelOptions,
    DelegationParamsCodec,
    INVALID_PARAMS_ERROR_CODE,
  } from "$lib/utils/transport/utils";
  import { authorizationStore } from "$lib/stores/authorization.store";
  import { z } from "zod";
  import FeaturedIcon from "$lib/components/ui/FeaturedIcon.svelte";
  import Button from "$lib/components/ui/Button.svelte";
  import Dialog from "$lib/components/ui/Dialog.svelte";
  import { CircleAlertIcon, RotateCcwIcon } from "@lucide/svelte";
  import { type Snippet } from "svelte";
  import { goto } from "$app/navigation";
  import { PostMessageUnsupportedError } from "$lib/utils/transport/postMessage";
  import { isCanisterError } from "$lib/utils/utils";

  class AuthorizeChannelError extends Error {
    #title: string;
    #description: string;

    constructor(title: string, description: string) {
      super(`${title}: ${description}`);
      this.#title = title;
      this.#description = description;
    }

    get title() {
      return this.#title;
    }

    get description() {
      return this.#description;
    }
  }

  type Props = {
    options?: ChannelOptions;
    children: Snippet;
  };

  const { options, children }: Props = $props();

  const authorizeParams =
    typeof window === "undefined"
      ? new URLSearchParams()
      : new URL(window.location.href).searchParams;
  const nativeRequestId = authorizeParams.get("native_request_id");
  const isNativeOidcAuthorizeRequest =
    nativeRequestId === null &&
    authorizeParams.get("response_type") === "code" &&
    authorizeParams.has("client_id");

  const authorizeChannel = (channel: Channel): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      channel.addEventListener("request", async (request) => {
        if (
          request.id === undefined ||
          request.method !== "icrc34_delegation" ||
          $authorizationStore !== undefined
        ) {
          // Ignore if it's a different method, or we're already processing
          return;
        }
        const result = DelegationParamsCodec.safeParse(request.params);
        if (!result.success) {
          await channel.send({
            jsonrpc: "2.0",
            id: request.id,
            error: {
              code: INVALID_PARAMS_ERROR_CODE,
              message: z.prettifyError(result.error),
            },
          });
          reject(
            new AuthorizeChannelError(
              $t`Invalid request`,
              $t`It seems like an invalid authentication request was received.`,
            ),
          );
          return;
        }
        try {
          await authorizationStore.handleRequest(
            channel.origin,
            request.id,
            result.data,
          );
          resolve();
        } catch (error) {
          console.error(error); // Log error to console
          reject(
            new AuthorizeChannelError(
              $t`Unverified origin`,
              $t`It seems like the request could not be processed.`,
            ),
          );
        }
      });
    });

  const authorizeNativeRequest = async (requestId: string): Promise<void> => {
    try {
      await authorizationStore.handleNativeRequest(requestId);
    } catch (error) {
      if (isCanisterError(error)) {
        if (
          error.type === "expired" ||
          error.type === "not_found" ||
          error.type === "already_completed"
        ) {
          throw new AuthorizeChannelError(
            $t`Invalid request`,
            $t`It seems like an invalid authentication request was received.`,
          );
        }
      }
      throw error;
    }
  };

  const authorizeNativeOidcRequest = async (): Promise<void> => {
    try {
      await authorizationStore.handleNativeOidcAuthorizeRequest(authorizeParams);
    } catch (error) {
      if (isCanisterError(error)) {
        if (
          error.type === "invalid_origin" ||
          error.type === "invalid_redirect_uri" ||
          error.type === "invalid_request" ||
          error.type === "too_many_requests"
        ) {
          throw new AuthorizeChannelError(
            $t`Invalid request`,
            $t`It seems like an invalid authentication request was received.`,
          );
        }
      }
      if (
        error instanceof Error &&
        error.message.startsWith("Invalid native OIDC authorization request:")
      ) {
        throw new AuthorizeChannelError(
          $t`Invalid request`,
          $t`It seems like an invalid authentication request was received.`,
        );
      }
      throw error;
    }
  };

  let authorizePromise = $state(
    nativeRequestId !== null
      ? authorizeNativeRequest(nativeRequestId)
      : isNativeOidcAuthorizeRequest
        ? authorizeNativeOidcRequest()
      : channelStore
          .establish(options)
          .catch((error) => {
            console.error(error); // Log error to console
            if (error instanceof PostMessageUnsupportedError) {
              goto("/unsupported");
              return new Promise<Channel>(() => {}); // Never resolve since we render the unsupported page
            }
            return Promise.reject(
              new AuthorizeChannelError(
                $t`Unable to connect`,
                $t`There was an issue connecting with the application. Try a different browser; if the issue persists, contact the developer.`,
              ),
            );
          })
          .then((channel) => {
            if (options?.pending === true) {
              // Don't authorize if we're only doing an initial handshake
              return;
            }
            // Replace promise when channel closes after it was established
            channel.addEventListener("close", () => {
              authorizePromise = Promise.reject(
                new AuthorizeChannelError(
                  $t`Connection closed`,
                  $t`It seems like the connection with the service could not be established. Try a different browser; if the issue persists, contact support.`,
                ),
              );
            });
            return authorizeChannel(channel);
          }),
  );
</script>

{#await authorizePromise then _}
  {@render children()}
{:catch error}
  {@const title =
    error instanceof AuthorizeChannelError ? error.title : $t`Unexpected error`}
  {@const message =
    error instanceof AuthorizeChannelError
      ? error.description
      : error instanceof Error
        ? error.message
        : $t({
            message: "Something went wrong",
            context:
              "Fallback error message when an unexpected error is caught",
          })}
  <Dialog>
    <FeaturedIcon size="lg" variant="error" class="mb-4 self-start">
      <CircleAlertIcon class="size-6" />
    </FeaturedIcon>
    <h1 class="text-text-primary mb-3 text-2xl font-medium">{title}</h1>
    <p class="text-text-tertiary mb-6 text-base font-medium">{message}</p>
    <Button onclick={() => window.close()} variant="secondary">
      <RotateCcwIcon class="size-4" />
      <span>{$t`Return to app`}</span>
    </Button>
  </Dialog>
{/await}
