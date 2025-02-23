# **Spring Cloud Gateway ile JWT Doğrulama ve Role-Based Yetkilendirme / JWT Authentication and Role-Based Authorization with Spring Cloud Gateway**

Bu proje, **Spring Cloud Gateway** kullanarak **JWT doğrulama** ve **role-based yetkilendirme** işlemlerini gerçekleştiren bir API Gateway uygulamasıdır. / This project is an API Gateway application using **Spring Cloud Gateway** for **JWT authentication** and **role-based authorization**.

## **🚀 Proje Özellikleri / Project Features**
- **Spring Cloud Gateway** kullanılarak merkezi API yönlendirme sağlanır. / **Central API routing** with **Spring Cloud Gateway**.
- **WebClient** ile **Auth Service** üzerinden JWT doğrulama yapılır. / **JWT validation** via **Auth Service** using **WebClient**.
- **Global Filters** ile **Token ve Role doğrulaması** gerçekleştirilir. / **Global Filters** for **Token and Role validation**.
- **Spring Boot Config (YAML) ile dinamik role yönetimi** sağlanır. / **Dynamic role management** via **Spring Boot Config (YAML)**.
- **Modüler YAML yapılandırması** ile ortam bazlı konfigürasyon yönetimi yapılır. / **Modular YAML configuration** for environment-based settings.
- **Önce `TokenValidationFilter`, sonra `RoleValidationFilter` çalışacak şekilde filtre sırası belirlenir.** / **Filters are executed in order: `TokenValidationFilter` first, then `RoleValidationFilter`.**

---

## **📌 Proje Yapısı / Project Structure**
```
📂 src/main/java/com/example/gateway
 ├── 📂 client
 │   ├── AuthClient.java
 │
 ├── 📂 filter
 │   ├── TokenValidationFilter.java
 │   ├── RoleValidationFilter.java
 │
 ├── 📂 config
 │   ├── WebClientConfig.java
 │
 ├── 📂 resources
 │   ├── application.yml
 │   ├── application-gateway.yml
 │   ├── application-webclient.yml
```

---

## **🛠️ Kullanılan Teknolojiler / Technologies Used**
- **Java 21**
- **Spring Boot 3.x**
- **Spring Cloud Gateway 4.x**
- **Spring WebFlux & WebClient**
- **Lombok**
- **Maven**

---

## **📌 API Gateway Mantığı / API Gateway Logic**
Bu projede **iki filtre** kullanılmaktadır: / This project utilizes **two filters**:

1️⃣ **TokenValidationFilter** → **Önce çalışır / Executes first**
- `Authorization` header içindeki token’ı alır. / Extracts the token from the `Authorization` header.
- `Auth Service` üzerinden **token doğrulaması yapar.** / **Validates the token** via `Auth Service`.
- Token geçerli ise isteğe devam eder, **geçersizse `401 Unauthorized` döner.** / Proceeds if the token is valid, otherwise **returns `401 Unauthorized`.**

2️⃣ **RoleValidationFilter** → **İkinci olarak çalışır / Executes second**
- `Auth Service` üzerinden **kullanıcının rolünü alır.** / **Retrieves the user's role** from `Auth Service`.
- İstek yapılan **endpoint’in `metadata.allowedRoles` listesi ile rolü karşılaştırır.** / **Compares the user role with the `metadata.allowedRoles` list** of the requested endpoint.
- Eğer kullanıcının rolü uygun değilse, **`403 Forbidden` hatası döner.** / If the role is not authorized, **returns `403 Forbidden`.**

---

## **📌 `application-gateway.yml` Konfigürasyonu / Configuration**

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: payment-service
          uri: ${ENV_PAYMENT_SERVICE_URI:http://localhost:8082}
          predicates:
            - Path=/payment/**
          metadata:
            allowedRoles: ["ADMIN", "MODERATOR", "USER"]

        - id: customer-service
          uri: ${ENV_CUSTOMER_SERVICE_URI:http://localhost:8083}
          predicates:
            - Path=/customer/**
          metadata:
            allowedRoles: ["ADMIN", "MODERATOR"]

        - id: admin-service
          uri: ${ENV_ADMIN_SERVICE_URI:http://localhost:8084}
          predicates:
            - Path=/admin/**
          metadata:
            allowedRoles: ["ADMIN"]
```

---

## **✅ Projeyi Çalıştırma / Running the Project**
**1️⃣ Maven bağımlılıklarını yükleyin ve projeyi temiz derleyin:** / **Load dependencies and build the project:**
```bash
mvn clean package
```

**2️⃣ Spring Boot uygulamasını başlatın:** / **Start the Spring Boot application:**
```bash
mvn spring-boot:run
```

---

## **📌 Özet / Summary**
| **Özellik / Feature** | **Açıklama / Description** |
|------------|-------------|
| **API Gateway** | **Spring Cloud Gateway kullanarak merkezi API yönlendirme / Central API routing with Spring Cloud Gateway** |
| **JWT Doğrulama / JWT Authentication** | **Auth Service üzerinden WebClient ile token doğrulama / Token validation via Auth Service using WebClient** |
| **Role-Based Yetkilendirme / Role-Based Authorization** | **Her servise erişim, roller üzerinden kontrol edilir / Access control based on user roles** |
| **Modüler Config Yapısı / Modular Configuration** | **application-gateway.yml ile dinamik roller yönetimi / Dynamic role management via application-gateway.yml** |
| **Öncelikli Filtre Çalıştırma / Prioritized Filter Execution** | **Önce Token Validation, sonra Role Validation çalışır / Token validation first, then role validation** |

📌 **Bu proje ile, Spring Cloud Gateway üzerinde JWT tabanlı doğrulama ve yetkilendirme işlemlerini başarıyla yönetebilirsiniz! / With this project, you can successfully manage JWT authentication and role-based authorization on Spring Cloud Gateway!** 🚀🔥

