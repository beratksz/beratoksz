# 1️ Taban imajı (AspNet Core Çalışma Zamanı)
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080

# 2️ Build ve Restore (SDK Kullanan Katman)
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["beratoksz/beratoksz.csproj", "beratoksz/"]
RUN dotnet restore "beratoksz/beratoksz.csproj"

# 3️ Tüm dosyaları kopyala ve derleme işlemi yap
COPY . .
WORKDIR "/src/beratoksz"
RUN dotnet build "beratoksz.csproj" -c $BUILD_CONFIGURATION -o /app/build

# 4️ Uygulamayı yayına hazır hale getir (Publish)
FROM build AS publish
RUN dotnet publish "beratoksz.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# 5️ Final Katman: Production İçin Optimize Edilmiş
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# 6️ Daha iyi hata ayıklama için çevre değişkenlerini kontrol et
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_RUNNING_IN_CONTAINER=true

# 7️ Uygulamayı başlat
ENTRYPOINT ["dotnet", "beratoksz.dll"]
