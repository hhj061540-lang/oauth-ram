# Use a lightweight Node.js image
FROM node:20-alpine

# Set working directory inside the container
WORKDIR /app

# Install wget to fetch the server script
RUN apk add --no-cache wget

# Download the server script from your GitHub repository
RUN wget https://raw.githubusercontent.com/hhj061540-lang/oauth-ram/refs/heads/main/server.js -O server.js

# Install dependencies
RUN npm install express jsonwebtoken

# Expose the application port
EXPOSE 5900

# Start the Node.js server
CMD ["node", "server.js"]
