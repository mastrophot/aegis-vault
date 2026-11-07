FROM node:20-alpine AS runner

WORKDIR /app

# Install build tools for native crypto bindings if needed
RUN apk add --no-cache python3 make g++

# Copy dependency specifications
COPY package.json package-lock.json ./

# Install production dependencies
RUN npm install --omit=dev

# Copy application source code
COPY . .

# Default environment configuration
ENV NODE_ENV=production \
    PORT=8080 \
    NEAR_NETWORK=testnet \
    CONTRACT_ID=aegis.okgoogleok.testnet \
    RELAYER_ACCOUNT_ID=keeper.aegis.okgoogleok.testnet \
    NEAR_RPC_URL=https://test.rpc.fastnear.com \
    SOLANA_RPC_URL=https://solana-devnet.api.onfinality.io/public \
    EVM_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

CMD ["node", "relayer/service.js", "--server"]
