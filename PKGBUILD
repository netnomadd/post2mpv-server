# Maintainer: your name <your@email.com>
pkgname=post2mpv-server
pkgver=1.0.0
pkgrel=1
pkgdesc="HTTP server for mpv/peerflix/yt-dlp control"
arch=('x86_64')
url="https://github.com/netnomadd/post2mpv-server"
license=('MIT')
depends=('mpv')
optdepends=(
    'yt-dlp: for download action'
    'peerflix: for torrent playback'
    'vot-cli-live: for translate action'
)
makedepends=('go')
install="$pkgname.install"
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    export CGO_ENABLED=0
    export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"
    go build -ldflags "-linkmode=external -extldflags $LDFLAGS" -o post2mpv .
}

package() {
    cd "$pkgname-$pkgver"

    install -Dm755 post2mpv         "$pkgdir/usr/bin/post2mpv"
    install -Dm755 vot              "$pkgdir/usr/bin/vot"
    install -Dm644 post2mpv.service "$pkgdir/usr/lib/systemd/user/post2mpv.service"
}
