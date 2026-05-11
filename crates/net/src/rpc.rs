use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    request_response::{self, Behaviour as RrBehaviour, Config as RrConfig, ProtocolSupport},
    StreamProtocol,
};
use std::{io, iter, time::Duration};

use crate::serializer::{from_cbor_fetch, from_cbor_frame, to_cbor_fetch, to_cbor_frame};
use crate::types::{FetchMissing, RpcFrame};

/// /ecac/fetch/1
const FETCH_PROTO: StreamProtocol = StreamProtocol::new("/ecac/fetch/1");

#[derive(Clone, Default)]
pub struct FetchCodec;

#[async_trait]
impl request_response::Codec for FetchCodec {
    type Protocol = StreamProtocol;
    type Request = FetchMissing;
    type Response = RpcFrame;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        from_cbor_fetch(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        from_cbor_frame(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = to_cbor_fetch(&req);
        io.write_all(&bytes).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = to_cbor_frame(&resp);
        io.write_all(&bytes).await?;
        io.close().await
    }
}

/// Build a RequestResponse behaviour for `/ecac/fetch/1`.
pub fn build_fetch_behaviour() -> RrBehaviour<FetchCodec> {
    let protocols = iter::once((FETCH_PROTO.clone(), ProtocolSupport::Full));
    // Bump the request timeout; RR itself has no keep-alive knob in this API.
    // (Connection idle keep-alive is controlled via swarm::Config, not here.)
    let cfg = RrConfig::default().with_request_timeout(Duration::from_secs(30));
    RrBehaviour::<FetchCodec>::new(protocols, cfg)
}
