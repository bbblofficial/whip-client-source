#pragma once
#include <math.h>
#include <random>

#define PI 3.1415926535897931

static double boxMuller(double mean, double stddev) {
    double u1 = 1.0 - rand() / (double)(RAND_MAX + 1);
    double u2 = 1.0 - rand() / (double)(RAND_MAX + 1);

    double randStd = sqrt(-2.0 * log(u1)) * sin(2.0 * PI * u2);

    return mean + stddev * randStd;
}

static double randomDouble(double min, double max) {
	return (max - min) * ((double) rand() / (double)RAND_MAX) + min;
}

static float randomFloat(float min, float max) {
	return (max - min) * ((float)rand() / (float)RAND_MAX) + min;
}

static int randomInt(int min, int max) {
    return min + rand() % ((max + 1) - min);
}

static double radtodeg(double x) {
	return x * 180.0 / 3.14159265359;
}

static double distance(double x, double z) {
	return sqrt(pow(x, 2) + pow(z, 2));
}

static double distance3D(double* x, double* y) {
	return sqrt(pow(x[0] - y[0], 2) + pow(x[1] - y[1], 2) + pow(x[2] - y[2], 2));
}

static void direction3D(double* x, double* y, double* output) {
	double dx = x[0] - y[0];
	double dy = x[1] - y[1];
	double dz = x[2] - y[2];
	*output = radtodeg(atan2(dz, dx)) - 90.0;
	output[1] = radtodeg(-atan(dy / distance(dx, dz)));
}

static float angleTo180(float f)
{
	f = fmodf(f, 360.0f);

	if (f >= 180.0f)
	{
		f -= 360.0f;
	}

	if (f < -180.0f)
	{
		f += 360.0f;
	}

	return f;
}

static double directionYaw(double x, double z) {
	return radtodeg(atan2(z, x)) - 90.0;
}

static float getYawToRotation(float playerYaw, float goToYaw) {
	float a = playerYaw - goToYaw;
	float b = 360 - abs(a);
	if (abs(a) < b) return -a;
	if (a < 0) return -b;
	return b;
}

inline const char* intToString(int value) {
	static char buffer[16];
	char* ptr = buffer + 15;
	*ptr = '\0';

	bool isNegative = false;
	if (value < 0) {
		isNegative = true;
		value = -value;
	}

	if (value == 0) {
		*(--ptr) = '0';
	} else {
		while (value > 0) {
			*(--ptr) = '0' + (value % 10);
			value /= 10;
		}
	}

	if (isNegative) {
		*(--ptr) = '-';
	}

	return ptr;
}

struct Vec2 {
	float x, y;

	Vec2() : x(0), y(0) {}
	Vec2(float x, float y) : x(x), y(y) {}

	Vec2 operator-(const Vec2& other) const {
		return Vec2(x - other.x, y - other.y);
	}
};

struct Vec3 {
	float x, y, z;
	Vec3() : x(0), y(0), z(0) {}
	Vec3(float x, float y, float z) : x(x), y(y), z(z) {}

	float length() const {
		return sqrt(x * x + y * y + z * z);
	}

	Vec3 operator-(const Vec3& other) const {
		return Vec3(x - other.x, y - other.y, z - other.z);
	}
};

struct Vec3D
{
	double x, y, z;

	double distance(const Vec3D& other) const
	{
		return sqrt(pow(x - other.x, 2.0) + pow(y - other.y, 2.0) + pow(z - other.z, 2.0));
	}

	Vec3D() = default;

	Vec3D(int i, int i1, int i2) : x(i), y(i1), z(i2) {}
};

struct Vec4 {
	float x, y, z, w;
	Vec4() : x(0), y(0), z(0), w(0) {}
	Vec4(float x, float y, float z, float w) : x(x), y(y), z(z), w(w) {}
};

template <typename T> class Vector2;
template <typename T> class Vector3;
template <typename T> class Vector4;

template <typename T>
class Vector2 {
public:
    T X;
    T Y;

    Vector2() : X(0), Y(0) {}
    Vector2(T A, T B) : X(A), Y(B) {}

    T Distance(const Vector2<T>& Other) const {
        return std::sqrt(std::pow(X - Other.X, 2.0) + std::pow(Y - Other.Y, 2.0));
    }

    Vector2 operator-(const Vector2<T>& Other) const { return Vector2(X - Other.X, Y - Other.Y); }
    Vector2 operator+(const Vector2<T>& Other) const { return Vector2(X + Other.X, Y + Other.Y); }

    Vector2 Rotate(double Angle, const Vector2<T>& Center) {
        double Radians = Angle * PI / 180.0;
        double CosTheta = std::cos(Radians);
        double SinTheta = std::sin(Radians);

        T TranslatedX = X - Center.X;
        T TranslatedY = Y - Center.Y;

        return Vector2(
            TranslatedX * CosTheta - TranslatedY * SinTheta + Center.X,
            TranslatedX * SinTheta + TranslatedY * CosTheta + Center.Y
        );
    }
};

template <typename T>
class Vector3 {
public:
	T X;
	T Y;
	T Z;

	Vector3();
	Vector3(T A, T B, T C);

	template <class U>
	Vector3(const Vector3<U>& Other);

	bool World2Screen(Vector2<float>& ScreenProjection, const std::vector<float>& ModelView, const std::vector<float>& Projection, const int Width, const int Height);

	T Distance(const Vector3<T>& Other) const;
	T DistanceSq(const Vector3<T>& Other) const;
	T Dot(const Vector3<T>& Other) const;
	Vector3 Normalized() const;
	T Length() const;
	Vector3 operator-(const Vector3<T>& Other) const;
	Vector3 operator+(const Vector3<T>& Other) const;
	Vector3 operator*(const Vector3<T>& Other) const;
	Vector3 operator*(const T& Scalar) const;
	Vector3 operator/(const T& Scalar) const;

	float& operator[](int I) {
		return ((float*)this)[I];
	}

	float operator[](int I) const {
		return ((float*)this)[I];
	}
};

template <typename T>
Vector3<T>::Vector3() : X(0), Y(0), Z(0) {}

template <typename T>
Vector3<T>::Vector3(T A, T B, T C) : X(A), Y(B), Z(C) {}

template <typename T>
template<typename U>
Vector3<T>::Vector3(const Vector3<U>& Other) : X(static_cast<T>(Other.X)), Y(static_cast<T>(Other.Y)), Z(static_cast<T>(Other.Z)) {}

template <typename T>
T Vector3<T>::Distance(const Vector3<T>& Other) const {
	return sqrtf(pow(X - Other.X, 2.0) + pow(Y - Other.Y, 2.0) + pow(Z - Other.Z, 2.0));
}

template <typename T>
T Vector3<T>::DistanceSq(const Vector3<T>& Other) const
{
	float dx = X - Other.X;
	float dy = Y - Other.Y;
	float dz = Z - Other.Z;
	return dx * dx + dy * dy + dz * dz;
}

template <typename T>
T Vector3<T>::Dot(const Vector3<T>& Other) const {
	return X * Other.X + Y * Other.Y + Z * Other.Z;
}

template <typename T>
T Vector3<T>::Length() const {
	return sqrt(X * X + Y * Y + Z * Z);
}

template <typename T>
Vector3<T> Vector3<T>::Normalized() const {
	T len = Length();
	if (len > 0) {
		return Vector3(X / len, Y / len, Z / len);
	}
	return Vector3(0, 0, 0);
}

template <typename T>
Vector3<T> Vector3<T>::operator-(const Vector3<T>& Other) const {
	return Vector3(X - Other.X, Y - Other.Y, Z - Other.Z);
}

template <typename T>
Vector3<T> Vector3<T>::operator+(const Vector3<T>& Other) const {
	return Vector3(X + Other.X, Y + Other.Y, Z + Other.Z);
}

template<typename T>
Vector3<T> Vector3<T>::operator*(const Vector3<T>& Other) const
{
	return Vector3(X * Other.X, Y * Other.Y, Z * Other.Z);
}

template <typename T>
Vector3<T> Vector3<T>::operator*(const T& Scalar) const {
	return Vector3(X * Scalar, Y * Scalar, Z * Scalar);
}

template <typename T>
Vector3<T> Vector3<T>::operator/(const T& Scalar) const {
	return Vector3(X / Scalar, Y / Scalar, Z / Scalar);
}

struct Vector3f {
	float x, y, z;

	constexpr Vector3f(float x = 0.0f, float y = 0.0f, float z = 0.0f)
		: x(x), y(y), z(z) {}

	Vector3f operator+(const Vector3f& other) const {
		return Vector3f(x + other.x, y + other.y, z + other.z);
	}

	Vector3f operator-(const Vector3f& other) const {
		return Vector3f(x - other.x, y - other.y, z - other.z);
	}

	Vector3f operator*(float scalar) const {
		return Vector3f(x * scalar, y * scalar, z * scalar);
	}

	float length() const {
		return std::sqrt(x * x + y * y + z * z);
	}

	Vector3f normalize() const {
		float len = length();
		return len > 0.0f ? Vector3f(x / len, y / len, z / len) : Vector3f();
	}
};

struct Vector3d {
	double x, y, z;

	constexpr Vector3d(double x = 0.0, double y = 0.0, double z = 0.0)
		: x(x), y(y), z(z) {}

	Vector3d operator+(const Vector3d& other) const {
		return Vector3d(x + other.x, y + other.y, z + other.z);
	}

	Vector3d operator-(const Vector3d& other) const {
		return Vector3d(x - other.x, y - other.y, z - other.z);
	}

	Vector3d operator*(double scalar) const {
		return Vector3d(x * scalar, y * scalar, z * scalar);
	}

	double length() const {
		return std::sqrt(x * x + y * y + z * z);
	}

	Vector3d normalize() const {
		double len = length();
		return len > 0.0 ? Vector3d(x / len, y / len, z / len) : Vector3d();
	}

	Vector3d Distance3d(const Vector3d& Other) const {
		return std::sqrt(std::pow(x - Other.x, 2) + std::pow(y - Other.y, 2) + std::pow(z - Other.z, 2));
	}
};

struct Color {
	float r, g, b, a;

	constexpr Color(float r = 1.0f, float g = 1.0f, float b = 1.0f, float a = 1.0f)
		: r(r), g(g), b(b), a(a) {}

	bool operator==(const Color& other) const {
		return r == other.r && g == other.g && b == other.b && a == other.a;
	}

	bool operator!=(const Color& other) const {
		return !(*this == other);
	}

	static const Color WHITE;
	static const Color BLACK;
	static const Color RED;
	static const Color GREEN;
	static const Color BLUE;
	static const Color YELLOW;
	static const Color CYAN;
	static const Color MAGENTA;
};

inline const Color Color::WHITE = Color(1.0f, 1.0f, 1.0f, 1.0f);
inline const Color Color::BLACK = Color(0.0f, 0.0f, 0.0f, 1.0f);
inline const Color Color::RED = Color(1.0f, 0.0f, 0.0f, 1.0f);
inline const Color Color::GREEN = Color(0.0f, 1.0f, 0.0f, 1.0f);
inline const Color Color::BLUE = Color(0.0f, 0.0f, 1.0f, 1.0f);
inline const Color Color::YELLOW = Color(1.0f, 1.0f, 0.0f, 1.0f);
inline const Color Color::CYAN = Color(0.0f, 1.0f, 1.0f, 1.0f);
inline const Color Color::MAGENTA = Color(1.0f, 0.0f, 1.0f, 1.0f);
