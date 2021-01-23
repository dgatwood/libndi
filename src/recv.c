#include <ndi/recv.h>
#include <ndi/scramble.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <unistd.h>
#endif

#if defined _WIN32
#if defined _WIN64
const char * _platformName = "WIN64";
#else
const char * _platformName = "WIN32";
#endif
#elif defined __linux__
const char * _platformName = "LINUX";
#elif defined __APPLE__
const char * _platformName = "APPLE";
#else
const char * _platformName = "UNKNOWN";
#endif

extern int errno;

typedef struct {
	int socket_fd;
	fd_set read_fds;
} internal_recv_context_t;


ndi_recv_context_t ndi_recv_create() {
	internal_recv_context_t * ctx = malloc(sizeof(internal_recv_context_t));
	memset(ctx, 0, sizeof(internal_recv_context_t));
	return ctx;
}

static void internal_write_u16(void * buffer, int offset, unsigned short v) {
	unsigned char * data = ((unsigned char*)buffer) + offset;
	data[0] = v & 0xFF;
	data[1] = v >> 8;
}

static void internal_write_u32(void * buffer, int offset, unsigned int v) {
	unsigned char * data = ((unsigned char*)buffer) + offset;
	data[0] = v & 0xFF;
	data[1] = (v >> 8) & 0xFF;
	data[2] = (v >> 16) & 0xFF;
	data[3] = (v >> 24) & 0xFF;
}

static void internal_write_u64(void * buffer, int offset, unsigned long long v) {
	unsigned char * data = ((unsigned char*)buffer) + offset;
	for (int i = 0; i < 8; i++) {
		data[i] = (v & 0xFF);
		v >>= 8;
	}
}

static int internal_send_meta(ndi_recv_context_t ctx, char * data) {
	
	internal_recv_context_t * internal = ctx;
	int data_len = strlen(data) + 1;
	int len = 20 + data_len;
	unsigned char * buffer = malloc(len);

	internal_write_u16(buffer, 0, 0x8001);
	internal_write_u16(buffer, 2, NDI_DATA_TYPE_METADATA);
	internal_write_u32(buffer, 4, 8); // info length
	internal_write_u32(buffer, 8, data_len);
	internal_write_u64(buffer, 12, 0);

	memcpy(buffer + 20, data, data_len);

	ndi_scramble_type1(buffer + 12, 8 + data_len, 8 + data_len);

	send(internal->socket_fd, buffer, len, 0);

cleanup:
	free(buffer);
    return 0;
}

int ndi_recv_send_metadata(ndi_recv_context_t ctx, ndi_packet_metadata_t * meta) {
	return internal_send_meta(ctx, meta->data);
}

int ndi_recv_connect(ndi_recv_context_t ctx, const char * host, unsigned short port) {

	internal_recv_context_t * internal = ctx;

#ifdef _WIN32
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif

	char port_str[10];
#ifdef _WIN32
	_itoa_s(port, port_str, sizeof(port_str), 10);
#else
	sprintf(port_str, "%d", port);
#endif

	int ret;
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = IPPROTO_IP;
	if ((ret = getaddrinfo(host, port_str, &hints, &res)) != 0) {
		return -1;
	}

	for (struct addrinfo * p = res; p != NULL; p = p->ai_next) {
		internal->socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (internal->socket_fd < 0)
			continue;

		ret = connect(internal->socket_fd, res->ai_addr, res->ai_addrlen);
		if (ret < 0) {
			freeaddrinfo(res);
			return -1;
		}
	}
	freeaddrinfo(res);

	if (internal->socket_fd <= 0)
		return -1;

	char meta[100];

	sprintf(meta, "<ndi_version text=\"3\" video=\"4\" audio=\"3\" sdk=\"3.5.1\" platform=\"%s\"/>", _platformName);
	ret = internal_send_meta(ctx, meta);

	sprintf(meta, "<ndi_video quality=\"high\"/>");
	ret = internal_send_meta(ctx, meta);

	sprintf(meta, "<ndi_enabled_streams video=\"true\" audio=\"true\" text=\"true\"/>");
	ret = internal_send_meta(ctx, meta);

	// <ndi_identify name=\"\"/>
	// <ndi_capabilities ntk_ptz="true" ntk_pan_tilt="true" ntk_zoom="true" ntk_iris="false" ntk_white_balance="false" ntk_exposure="false" ntk_record="false" web_control="" ndi_type="NDI"/>
	// <ndi_failover name=\"\" ip=\"\"/>
	// <ndi_product long_name=\"\" short_name=\"\" manufacturer=\"\" version=\"1.000.000\" session=\"default\" model_name=\"\" serial=\"\"/>

	return 0;
}

void ndi_recv_close(ndi_recv_context_t ctx) {

	internal_recv_context_t * internal = ctx;

	if (internal->socket_fd) {
#ifdef _WIN32
		closesocket(internal->socket_fd);
#else
		close(internal->socket_fd);
#endif
		internal->socket_fd = 0;
	}
}

int ndi_recv_is_connected(ndi_recv_context_t ctx) {
	internal_recv_context_t * internal = ctx;
	return internal->socket_fd > 0;
}

static int internal_recv(int socket, unsigned char * buf, int len) {
    int l = len;
    while (len > 0)
    {
        int n = recv(socket, (char*)buf, len, 0);
        if (n < 0)
            return n;
        len -= n;
        buf += n;
    }
    return l - len;
}

static void internal_unscramble(int type2, unsigned char *buf, int len, unsigned int seed) {
	if (!type2)
		ndi_unscramble_type1(buf, len, seed);
	else
		ndi_unscramble_type2(buf, len, seed);
}

int ndi_recv_wait(ndi_recv_context_t ctx, int timeout_ms) {

	internal_recv_context_t * internal = ctx;

	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&internal->read_fds);
	FD_SET(internal->socket_fd, &internal->read_fds);

	int status = select(internal->socket_fd + 1, &internal->read_fds, NULL, NULL, &tv);
	if (status <= 0) {
		if (errno == EBADF)
			ndi_recv_close(ctx);
		return -1;
	}

	return 0;
}

#pragma pack(1)
struct NDIHeader
{
    uint8_t version;
    uint8_t id;
    uint16_t packet_type;
    uint32_t info_len;
    uint32_t data_len;
};

struct NDIVideoInfoHeader
{
    uint32_t fourcc;
    uint32_t width;
    uint32_t height;
    uint32_t framerate_num;
    uint32_t framerate_den;
};
struct NDIAudioInfoHeader
{
    uint32_t fourcc;
    uint32_t num_samples;
    uint32_t num_channels;
    uint32_t sample_rate;
};
struct NDIMetaInfoHeader
{
    uint64_t timecode;
};
#pragma pack()

int ndi_recv_capture(ndi_recv_context_t ctx, ndi_packet_video_t * video, ndi_packet_audio_t * audio, ndi_packet_metadata_t * meta, int timeout_ms) {

	internal_recv_context_t * internal = ctx;
	int ret;

    ret = ndi_recv_wait(ctx, timeout_ms);
	if (ret < 0)
		return -1;

    struct NDIHeader header;

    int len = internal_recv(internal->socket_fd, (unsigned char*)&header, sizeof(header));
    if (len < sizeof(header))
        return -2;

    header.packet_type = le16toh(header.packet_type);
    header.info_len = le32toh(header.info_len);
    header.data_len = le32toh(header.data_len);
	unsigned int seed = header.info_len + header.data_len;

	if (header.id != 0x80)
		return -3;

	if (header.packet_type == NDI_DATA_TYPE_VIDEO && video) {

        struct NDIVideoInfoHeader *info = malloc(header.info_len);
		internal_recv(internal->socket_fd, (unsigned char*)info, header.info_len);
		internal_unscramble(header.version > 3, (unsigned char*)info, header.info_len, seed);

        video->fourcc = le32toh(info->fourcc);
        video->width = le32toh(info->width);
        video->height = le32toh(info->height);
        video->framerate_num = le32toh(info->framerate_num);
        video->framerate_den = le32toh(info->framerate_den);
        video->size = header.data_len;
        video->data = malloc(header.data_len);
        internal_recv(internal->socket_fd, video->data, header.data_len);

		free(info);
	}
	else if (header.packet_type == NDI_DATA_TYPE_AUDIO && audio) {

        struct NDIAudioInfoHeader *info = malloc(header.info_len);
		internal_recv(internal->socket_fd, (unsigned char*)info, header.info_len);
		internal_unscramble(header.version > 2, (unsigned char*)info, header.info_len, seed);

        audio->fourcc = le32toh(info->fourcc);
        audio->num_samples = le32toh(info->num_samples);
        audio->num_channels = le32toh(info->num_channels);
        audio->sample_rate = le32toh(info->sample_rate);
        audio->size = header.data_len;
        audio->data = malloc(header.data_len);
        internal_recv(internal->socket_fd, audio->data, header.data_len);

		free(info);
	}
	else if (header.packet_type == NDI_DATA_TYPE_METADATA && meta != NULL) {

		int chunk_len = header.info_len + header.data_len;
        struct NDIMetaInfoHeader *info = malloc(chunk_len);
		internal_recv(internal->socket_fd, (unsigned char*)info, chunk_len);
		internal_unscramble(header.version > 2, (unsigned char*)info, chunk_len, seed);

        meta->timecode = le64toh(info->timecode);
		meta->data = malloc(header.data_len);
		meta->size = header.data_len;
		memcpy(meta->data, (unsigned char*)info + header.info_len, header.data_len);

		free(info);
	}

	return header.packet_type;
}

void ndi_recv_free_video(ndi_packet_video_t * video) {
	free(video->data);
	video->data = NULL;
}

void ndi_recv_free_audio(ndi_packet_audio_t * audio) {
	free(audio->data);
	audio->data = NULL;
}

void ndi_recv_free_metadata(ndi_packet_metadata_t * meta) {
	free(meta->data);
	meta->data = NULL;
}

void ndi_recv_free(ndi_recv_context_t ctx) {

	internal_recv_context_t * internal = ctx;

	ndi_recv_close(ctx);

	free(ctx);
}
