# Users microservice Dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Fcg.Users.Api.csproj", "./"]
RUN dotnet restore "Fcg.Users.Api.csproj"
COPY . ./
RUN dotnet publish "Fcg.Users.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./

# Install curl for healthchecks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

ENV ASPNETCORE_URLS="http://+:{PORT}"
ENV ASPNETCORE_ENVIRONMENT=Production

# Default port for this service
ARG PORT=5001
EXPOSE ${PORT}

ENTRYPOINT ["dotnet", "Fcg.Users.Api.dll"]
