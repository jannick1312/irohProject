//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::BytesMut;
use iroh_base::SecretKey;
use n0_future::{Sink, Stream};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, Snafu};
use tracing::debug;

use super::KeyCache;
#[cfg(not(wasm_browser))]
use crate::{
    client::streams::{MaybeTlsStream, ProxyStream},
    protos::streams::WsBytesFramed,
};
use crate::{
    protos::{
        handshake,
        send_recv::{
            ClientToServerMsg, RecvError as RecvRelayError, SendError as SendRelayError,
            ServerToClientMsg, MAX_PAYLOAD_SIZE,
        },
    },
    MAX_PACKET_SIZE,
};

/// Error for sending messages to the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SendError {
    #[snafu(transparent)]
    WebsocketIo {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[snafu(display("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}"))]
    ExceedsMaxPacketSize { size: usize },
}

/// Errors when receiving messages from the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecvError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    ProtocolSend { source: SendRelayError },
    #[snafu(transparent)]
    ProtocolRecv { source: RecvRelayError },
    #[snafu(transparent)]
    Websocket {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
}

/// A connection to a relay server.
///
/// This holds a connection to a relay server.  It is:
///
/// - A [`Stream`] for [`ReceivedMessage`] to receive from the server.
/// - A [`Sink`] for [`SendMessage`] to send to the server.
/// - A [`Sink`] for [`Frame`] to send to the server.
///
/// The [`Frame`] sink is a more internal interface, it allows performing the handshake.
/// The [`SendMessage`] and [`ReceivedMessage`] are safer wrappers enforcing some protocol
/// invariants.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[debug("tokio_websockets::WebSocketStream")]
    #[cfg(not(wasm_browser))]
    pub(crate) conn: tokio_websockets::WebSocketStream<MaybeTlsStream<ProxyStream>>,
    #[debug("ws_stream_wasm::WsStream")]
    #[cfg(wasm_browser)]
    pub(crate) conn: ws_stream_wasm::WsStream,
    pub(crate) key_cache: KeyCache,
}

impl Conn {
    #[cfg(test)]
    pub(crate) fn test(io: tokio::io::DuplexStream) -> Self {
        use crate::protos::send_recv::MAX_FRAME_SIZE;
        Self {
            conn: tokio_websockets::ClientBuilder::new()
                .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
                .take_over(MaybeTlsStream::Test(io)),
            key_cache: KeyCache::test(),
        }
    }

    /// Constructs a new websocket connection, including the initial server handshake.
    #[cfg(wasm_browser)]
    pub(crate) async fn new(
        conn: ws_stream_wasm::WsStream,
        key_cache: KeyCache,
        secret_key: &SecretKey,
    ) -> Result<Self, handshake::Error> {
        let mut io = WsBytesFramed { io: conn };

        // exchange information with the server
        debug!("server_handshake: started");
        handshake::clientside(&mut io, secret_key).await?;
        debug!("server_handshake: done");

        Ok(Self {
            conn: io.io,
            key_cache,
        })
    }

    #[cfg(not(wasm_browser))]
    pub(crate) async fn new(
        conn: tokio_websockets::WebSocketStream<MaybeTlsStream<ProxyStream>>,
        key_cache: KeyCache,
        secret_key: &SecretKey,
    ) -> Result<Self, handshake::Error> {
        let mut io = WsBytesFramed { io: conn };

        // exchange information with the server
        debug!("server_handshake: started");
        handshake::clientside(&mut io, secret_key).await?;
        debug!("server_handshake: done");

        Ok(Self {
            conn: io.io,
            key_cache,
        })
    }
}

impl Stream for Conn {
    type Item = Result<ServerToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let msg = ready!(Pin::new(&mut self.conn).poll_next(cx));
        match msg {
            #[cfg(not(wasm_browser))]
            Some(Ok(msg)) => {
                if msg.is_close() {
                    // Indicate the stream is done when we receive a close message.
                    // Note: We don't have to poll the stream to completion for it to close gracefully.
                    return Poll::Ready(None);
                }
                if !msg.is_binary() {
                    tracing::warn!(?msg, "Got websocket message of unsupported type, skipping.");
                    return Poll::Pending;
                }
                let message =
                    ServerToClientMsg::from_bytes(msg.into_payload().into(), &self.key_cache);
                Poll::Ready(Some(message.map_err(Into::into)))
            }
            #[cfg(not(wasm_browser))]
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),

            #[cfg(wasm_browser)]
            Some(ws_stream_wasm::WsMessage::Binary(vec)) => {
                let frame = Frame::decode_from_ws_msg(Bytes::from(vec), &self.key_cache)?;
                Poll::Ready(Some(ReceivedMessage::try_from(frame)))
            }
            #[cfg(wasm_browser)]
            Some(msg) => {
                tracing::warn!(?msg, "Got websocket message of unsupported type, skipping.");
                Poll::Pending
            }

            None => Poll::Ready(None),
        }
    }
}

impl Sink<ClientToServerMsg> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: ClientToServerMsg) -> Result<(), Self::Error> {
        if let ClientToServerMsg::SendDatagrams { datagrams, .. } = &frame {
            let size = datagrams.contents.len();
            snafu::ensure!(size <= MAX_PAYLOAD_SIZE, ExceedsMaxPacketSizeSnafu { size });
        }

        #[cfg(not(wasm_browser))]
        let frame = tokio_websockets::Message::binary(tokio_websockets::Payload::from(
            frame.write_to(BytesMut::new()).freeze(),
        ));
        #[cfg(wasm_browser)]
        let frame = ws_stream_wasm::WsMessage::Binary(frame.write_to(Vec::new()));

        Pin::new(&mut self.conn)
            .start_send(frame)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}
