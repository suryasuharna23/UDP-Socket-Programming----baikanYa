Proyek ini saya kembangkan bersama teman baik saya, Muhammad Zidni Alkindi (18223071)

**README UDP SOCKET PROGRAMMING**

[ PROGRAM CHAT UDP SOCKET PROGRAMMING ]
Aplikasi ini adalah program chat berbasis UDP (User Datagram Protocol) yang dibuat menggunakan socket programming. 
Program ini memungkinkan komunikasi multi-pengguna di dalam satu jaringan lokal melalui server yang berfungsi mengelola koneksi dan pesan antar pengguna.

[ FITUR ]
1. Komunikasi Multi-Pengguna: Mendukung banyak pengguna dalam satu chat room yang sama.
2. Autentikasi Login: Setiap pengguna harus memasukkan username unik dan password untuk bergabung.
3. Broadcast Pesan: Pesan pengguna akan dikirimkan ke seluruh pengguna lain yang sedang aktif.
4. Notifikasi Pengguna: Notifikasi bergabung atau keluar dari chat room akan diberitahukan kepada pengguna lain.

[ PERSYARATAN SISTEM ]
1. Python versi 3.x
2. Koneksi jaringan lokal (untuk pengujian multi-pengguna)

[ STRUKTUR PROYEK ]
1. server.py: Program server yang menangani autentikasi, penerusan pesan, dan manajemen pengguna.
2. client.py: Program client yang digunakan pengguna untuk mengirim dan menerima pesan melalui server.

[ CARA PENGGUNAAN ]
1. Menjalankan Server:
Buka terminal, lalu jalankan server.py untuk memulai server pada IP dan port yang diinginkan.
Perintah:
python server.py
Server akan menunggu pengguna untuk bergabung ke dalam chat room.

2. Menjalankan Client:
Setiap pengguna dapat menjalankan client.py pada perangkat atau terminal berbeda.
Masukkan IP server, port, username, dan password ketika diminta.
Perintah:
python client.py

3. Pengujian Multi-Pengguna:
Jalankan client.py pada beberapa perangkat atau terminal untuk mensimulasikan interaksi multi-pengguna dalam jaringan lokal yang sama.

[ TEKNOLOGI YANG DIGUNAKAN ]
- Python: Bahasa pemrograman utama untuk implementasi server dan client.
- Socket Programming: Untuk mengatur komunikasi antar server dan client menggunakan protokol UDP.

[ BATASAN ]
- Jaringan Lokal: Aplikasi ini hanya mendukung jaringan lokal dan tidak direkomendasikan untuk internet publik tanpa VPN atau konfigurasi tambahan.
- Keamanan: Data yang dikirim tidak dienkripsi, sehingga keamanan komunikasi tergantung pada jaringan lokal.
