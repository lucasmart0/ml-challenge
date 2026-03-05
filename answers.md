# Preguntas teóricas — key_exchange

## 1. ¿Podrían enviarse los dos componentes de la KEK por el mismo canal? ¿Qué problema habría?

No debería hacerse. La división de la KEK en componentes XOR es una técnica de **split knowledge**: ningún componente individual revela información útil sobre la clave final. Sin embargo, la seguridad del esquema depende de que ambos componentes viajen por **canales independientes y de distintas bandas** (out-of-band).

Si ambos componentes se envían por el mismo canal (por ejemplo, dos emails), basta comprometer ese canal una sola vez para obtener ambos y reconstruir la KEK completa mediante XOR. Se pierde toda la ventaja de la distribución: el atacante que intercepta ese canal obtiene exactamente lo mismo que si hubiera viajado la clave entera.

En entornos PCI-DSS, el requisito 3.7.2 exige que el intercambio de claves criptográficas se realice de forma segura, y el uso de custodios separados con canales distintos es precisamente el mecanismo que lo garantiza.

## 2. ¿Qué método alternativo se te ocurre para que la contraparte entregue la KEK sin que viaje entera por un solo medio?

Varias alternativas, en orden de complejidad:

**a) Key ceremony presencial con sobre cerrado (método clásico PCI)**  
Cada componente es entregado por un custodio diferente en un sobre cerrado y firmado. Los custodios no conocen los componentes del otro. La recombinación ocurre en un HSM en presencia de ambos, con un auditor.

**b) Intercambio asimétrico (RSA o ECDH)**  
Cada parte genera un par de claves asimétricas. Se intercambian las claves públicas por un canal autenticado (TLS mutual, certificados X.509). Luego, la KEK o sus componentes se cifran con la clave pública del destinatario, garantizando que solo quien tiene la clave privada puede recuperarla. Este es el método preferido en integraciones modernas (Key Agreement per ISO 11770).

**c) Tres componentes con custodios distintos (M-of-N)**  
Dividir la KEK en tres componentes XOR en lugar de dos, requiriendo al menos dos para reconstruirla (esquema 2-of-3). Aumenta la resiliencia: incluso si un custodio es comprometido o no está disponible, la KEK sigue siendo recuperable.

**d) HSM-a-HSM directo**  
Usar la capacidad de TR-34 (ANSI X9.143 Part 2) para el transporte de claves entre HSMs usando infraestructura de clave pública (PKI). Cada HSM tiene un certificado que autentifica su identidad, y la clave se transporta cifrada de HSM a HSM sin que nadie la vea en claro en ningún momento.

## 3. Si una de las dos partes que custodian los componentes es comprometida, ¿queda comprometida la KEK? ¿Y si son las dos?

**Con un solo componente comprometido: NO.**  
Un componente XOR de una clave AES-256 es uniformemente aleatorio e independiente de la clave resultante. Conocer `C1` no revela ninguna información sobre la KEK (`C1 XOR C2`) porque `C2` puede ser cualquier valor posible de 32 bytes. El espacio de búsqueda sigue siendo 2²⁵⁶. La seguridad no se degrada en absoluto: es el principio de **perfect secrecy** del one-time pad aplicado a la distribución de claves.

**Con ambos componentes comprometidos: SÍ, completamente.**  
La KEK se reconstruye trivialmente: `KEK = C1 XOR C2`. No existe ningún mecanismo adicional de protección una vez que el atacante tiene ambos componentes. Por eso es crítico que:
- Los custodios sean personas o sistemas independientes.
- Los canales de distribución sean distintos e idealmente de distinta naturaleza (email + teléfono, digital + físico).
- Exista un proceso de detección de compromiso (alertas, auditoría de acceso a los componentes).

En esquemas M-of-N con N>2, la resistencia al compromiso escala: en un esquema 2-of-3, comprometer un solo custodio es insuficiente; se necesitan al menos dos.
