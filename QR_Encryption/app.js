/* ==========================================
   QR CRYPTOGRAPHY SYSTEM
   ========================================== */


// ==========================================
// HELPER
// ==========================================

const $ = (id) =>
    document.getElementById(id);


// ==========================================
// VARIABLES
// ==========================================

let protectedBlob = null;

let lastDestination = null;


// ==========================================
// TAB NAVIGATION
// ==========================================

document
    .querySelectorAll(".tab")
    .forEach(tab => {

        tab.addEventListener("click", () => {

            document
                .querySelectorAll(".tab")
                .forEach(t =>
                    t.classList.remove("active")
                );


            document
                .querySelectorAll(".page")
                .forEach(p =>
                    p.classList.remove("active")
                );


            tab.classList.add("active");


            $(tab.dataset.page)
                .classList.add("active");

        });

    });


// ==========================================
// FILE PREVIEW
// ==========================================

$("encryptFile")
    .addEventListener("change", () => {

        const file =
            $("encryptFile").files[0];


        if (!file)
            return;


        const url =
            URL.createObjectURL(file);


        $("inputPreview").src = url;


        $("inputPreview")
            .style.display = "inline-block";

    });


// ==========================================
// TEXT ENCODER / DECODER
// ==========================================

const encoder =
    new TextEncoder();


const decoder =
    new TextDecoder();


// ==========================================
// BASE64
// ==========================================

function bytesToBase64(bytes) {

    let binary = "";


    bytes.forEach(byte => {

        binary +=
            String.fromCharCode(byte);

    });


    return btoa(binary);

}


function base64ToBytes(base64) {

    const binary =
        atob(base64);


    return Uint8Array.from(
        binary,
        character =>
            character.charCodeAt(0)
    );

}


// ==========================================
// RANDOM BYTES
// ==========================================

function randomBytes(length) {

    const bytes =
        new Uint8Array(length);


    crypto.getRandomValues(bytes);


    return bytes;

}


// ==========================================
// CREATE ENCRYPTION KEY
// PBKDF2 → AES-256-GCM
// ==========================================

async function deriveKey(
    password,
    salt
) {

    const passwordKey =
        await crypto.subtle.importKey(

            "raw",

            encoder.encode(password),

            "PBKDF2",

            false,

            ["deriveKey"]

        );


    return crypto.subtle.deriveKey(

        {

            name: "PBKDF2",

            salt: salt,

            iterations: 150000,

            hash: "SHA-256"

        },

        passwordKey,

        {

            name: "AES-GCM",

            length: 256

        },

        false,

        [

            "encrypt",

            "decrypt"

        ]

    );

}


// ==========================================
// ENCRYPT
// ==========================================

async function encryptText(
    plainText,
    password
) {

    // Generate random salt
    const salt =
        randomBytes(16);


    // Generate random IV
    const iv =
        randomBytes(12);


    // Create encryption key
    const key =
        await deriveKey(
            password,
            salt
        );


    // Encrypt QR data
    const encrypted =
        await crypto.subtle.encrypt(

            {

                name: "AES-GCM",

                iv: iv

            },

            key,

            encoder.encode(
                plainText
            )

        );


    // Package encrypted information
    return JSON.stringify({

        version: 1,

        algorithm: "AES-256-GCM",

        kdf: "PBKDF2-SHA256",

        iterations: 150000,

        salt:
            bytesToBase64(salt),

        iv:
            bytesToBase64(iv),

        data:
            bytesToBase64(
                new Uint8Array(
                    encrypted
                )
            )

    });

}


// ==========================================
// DECRYPT
// ==========================================

async function decryptText(
    packageText,
    password
) {

    let packageData;


    try {

        packageData =
            JSON.parse(packageText);

    }

    catch {

        throw new Error(
            "Invalid encrypted data."
        );

    }


    // Validate encrypted package
    if (
        !packageData.salt ||
        !packageData.iv ||
        !packageData.data
    ) {

        throw new Error(
            "Invalid protected QR data."
        );

    }


    const salt =
        base64ToBytes(
            packageData.salt
        );


    const iv =
        base64ToBytes(
            packageData.iv
        );


    const encryptedData =
        base64ToBytes(
            packageData.data
        );


    // Use stored iteration count
    // if available
    const passwordKey =
        await crypto.subtle.importKey(

            "raw",

            encoder.encode(password),

            "PBKDF2",

            false,

            ["deriveKey"]

        );


    const key =
        await crypto.subtle.deriveKey(

            {

                name: "PBKDF2",

                salt: salt,

                iterations:
                    packageData.iterations ||
                    150000,

                hash: "SHA-256"

            },

            passwordKey,

            {

                name: "AES-GCM",

                length: 256

            },

            false,

            [

                "encrypt",

                "decrypt"

            ]

        );


    try {

        const decrypted =
            await crypto.subtle.decrypt(

                {

                    name: "AES-GCM",

                    iv: iv

                },

                key,

                encryptedData

            );


        return decoder.decode(
            decrypted
        );

    }

    catch {

        throw new Error(
            "Incorrect password or corrupted protected QR."
        );

    }

}


// ==========================================
// LOAD IMAGE
// ==========================================

async function loadImage(file) {

    return new Promise(
        (resolve, reject) => {

            const img =
                new Image();


            img.onload = () =>
                resolve(img);


            img.onerror = () =>
                reject(
                    new Error(
                        "Unable to load image."
                    )
                );


            img.src =
                URL.createObjectURL(file);

        }
    );

}


// ==========================================
// READ QR CODE
// ==========================================

async function decodeQrImage(file) {

    const img =
        await loadImage(file);


    const canvas =
        $("hiddenCanvas");


    const context =
        canvas.getContext(
            "2d",
            {
                willReadFrequently: true
            }
        );


    /*
        Limit image size so very large
        images do not overload the browser.
    */

    const maxSize = 1400;


    const scale =
        Math.min(

            1,

            maxSize /
            Math.max(
                img.naturalWidth,
                img.naturalHeight
            )

        );


    canvas.width =
        Math.floor(
            img.naturalWidth *
            scale
        );


    canvas.height =
        Math.floor(
            img.naturalHeight *
            scale
        );


    context.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );


    context.drawImage(

        img,

        0,
        0,

        canvas.width,
        canvas.height

    );


    const imageData =
        context.getImageData(

            0,
            0,

            canvas.width,
            canvas.height

        );


    const result =
        jsQR(

            imageData.data,

            imageData.width,

            imageData.height,

            {

                inversionAttempts:
                    "attemptBoth"

            }

        );


    /*
        Release image URL
    */

    if (img.src.startsWith("blob:")) {

        URL.revokeObjectURL(
            img.src
        );

    }


    if (!result) {

        throw new Error(
            "No readable QR Code was found. Please upload a clear protected QR image."
        );

    }


    return result.data;

}


// ==========================================
// GENERATE QR CODE
// ==========================================

async function generateQR(
    text,
    canvas,
    size = 500
) {

    await QRCode.toCanvas(

        canvas,

        text,

        {

            width: size,

            margin: 4,

            errorCorrectionLevel: "H"

        }

    );

}


// ==========================================
// ENCRYPT BUTTON
// ==========================================

$("encryptBtn")
    .addEventListener(
        "click",
        async () => {

            const status =
                $("encryptStatus");


            status.className =
                "status";


            status.textContent = "";


            const file =
                $("encryptFile")
                    .files[0];


            const password =
                $("password")
                    .value;


            const confirmPassword =
                $("confirmPassword")
                    .value;


            // ==================================
            // CHECK FILE
            // ==================================

            if (!file) {

                status.textContent =
                    "Please upload a QR Code image.";

                status.classList.add(
                    "error"
                );

                return;

            }


            // ==================================
            // CHECK PASSWORD
            // ==================================

            if (!password) {

                status.textContent =
                    "Please enter a password.";

                status.classList.add(
                    "error"
                );

                return;

            }


            // ==================================
            // CHECK PASSWORD LENGTH
            // ==================================

            if (password.length < 4) {

                status.textContent =
                    "Password must contain at least 4 characters.";

                status.classList.add(
                    "error"
                );

                return;

            }


            // ==================================
            // CHECK CONFIRM PASSWORD
            // ==================================

            if (
                password !==
                confirmPassword
            ) {

                status.textContent =
                    "Passwords do not match.";

                status.classList.add(
                    "error"
                );

                return;

            }


            try {

                // ==================================
                // READ ORIGINAL QR
                // ==================================

                status.textContent =
                    "Reading QR Code...";


                const qrData =
                    await decodeQrImage(
                        file
                    );


                console.log(
                    "Original QR data:",
                    qrData
                );


                // ==================================
                // ENCRYPT QR DATA
                // ==================================

                status.textContent =
                    "Encrypting QR data...";


                const encryptedPackage =
                    await encryptText(

                        qrData,

                        password

                    );


                console.log(
                    "Encrypted package created."
                );


                // ==================================
                // GENERATE ENCRYPTED QR
                // ==================================

                status.textContent =
                    "Generating protected QR...";


                const encryptedQRCanvas =
                    document.createElement(
                        "canvas"
                    );


                await generateQR(

                    encryptedPackage,

                    encryptedQRCanvas,

                    600

                );


                /*
                    IMPORTANT:

                    Do NOT distort the actual QR.

                    The QR must remain readable by
                    jsQR when the user uploads it
                    during decryption.
                */

                const protectedCanvas =
                    encryptedQRCanvas;


                // ==================================
                // CONVERT TO IMAGE
                // ==================================

                const image =
                    protectedCanvas
                        .toDataURL(
                            "image/png"
                        );


                $("protectedPreview")
                    .src = image;


                $("protectedResult")
                    .classList.remove(
                        "hidden"
                    );


                // ==================================
                // PREPARE DOWNLOAD
                // ==================================

                protectedBlob =
                    await (

                        await fetch(image)

                    ).blob();


                // ==================================
                // SUCCESS
                // ==================================

                status.textContent =
                    "✓ QR successfully encrypted.";

                status.classList.add(
                    "success"
                );


            }

            catch (error) {

                console.error(
                    error
                );


                status.textContent =
                    error.message ||
                    "Encryption failed.";

                status.classList.add(
                    "error"
                );

            }

        }
    );


// ==========================================
// DOWNLOAD PROTECTED QR
// ==========================================

$("downloadProtected")
    .addEventListener(
        "click",
        () => {

            if (!protectedBlob)
                return;


            const url =
                URL.createObjectURL(
                    protectedBlob
                );


            const link =
                document.createElement(
                    "a"
                );


            link.href = url;


            link.download =
                "protected-qr.png";


            document.body.appendChild(
                link
            );


            link.click();


            document.body.removeChild(
                link
            );


            setTimeout(() => {

                URL.revokeObjectURL(
                    url
                );

            }, 1000);

        }
    );


// ==========================================
// DECRYPT BUTTON
// ==========================================

$("decryptBtn")
    .addEventListener(
        "click",
        async () => {

            const status =
                $("decryptStatus");


            status.className =
                "status";


            status.textContent = "";


            const file =
                $("decryptFile")
                    .files[0];


            const password =
                $("decryptPassword")
                    .value;


            // ==================================
            // CHECK PROTECTED QR FILE
            // ==================================

            if (!file) {

                status.textContent =
                    "Please upload the protected QR.";

                status.classList.add(
                    "error"
                );

                return;

            }


            // ==================================
            // CHECK PASSWORD
            // ==================================

            if (!password) {

                status.textContent =
                    "Please enter the password.";

                status.classList.add(
                    "error"
                );

                return;

            }


            try {

                // ==================================
                // READ UPLOADED PROTECTED QR
                // ==================================

                status.textContent =
                    "Reading protected QR...";


                /*
                    THIS IS THE IMPORTANT FIX.

                    The encrypted package is now
                    read directly from the uploaded
                    protected QR image.

                    It no longer uses sessionStorage.
                */

                const encryptedPackage =
                    await decodeQrImage(
                        file
                    );


                console.log(
                    "Encrypted QR data:",
                    encryptedPackage
                );


                // ==================================
                // DECRYPT
                // ==================================

                status.textContent =
                    "Checking password...";


                const originalData =
                    await decryptText(

                        encryptedPackage,

                        password

                    );


                // ==================================
                // SAVE DESTINATION
                // ==================================

                lastDestination =
                    originalData;


                // ==================================
                // GENERATE ORIGINAL QR
                // ==================================

                status.textContent =
                    "Recovering original QR...";


                await generateQR(

                    originalData,

                    $("originalQr"),

                    500

                );


                // ==================================
                // SHOW RECOVERED DATA
                // ==================================

                $("destinationText")
                    .textContent =
                    "Recovered data: " +
                    originalData;


                // ==================================
                // SHOW RESULT
                // ==================================

                $("originalResult")
                    .classList.remove(
                        "hidden"
                    );


                // ==================================
                // SUCCESS
                // ==================================

                status.textContent =
                    "✓ QR successfully decrypted.";

                status.classList.add(
                    "success"
                );


            }

            catch (error) {

                console.error(
                    error
                );


                status.textContent =
                    error.message ||
                    "Decryption failed.";

                status.classList.add(
                    "error"
                );

            }

        }
    );


// ==========================================
// DOWNLOAD ORIGINAL QR
// ==========================================

$("downloadOriginal")
    .addEventListener(
        "click",
        () => {

            const canvas =
                $("originalQr");


            if (!canvas.width)
                return;


            canvas.toBlob(

                blob => {

                    if (!blob)
                        return;


                    const url =
                        URL.createObjectURL(
                            blob
                        );


                    const link =
                        document.createElement(
                            "a"
                        );


                    link.href = url;


                    link.download =
                        "original-qr.png";


                    document.body.appendChild(
                        link
                    );


                    link.click();


                    document.body.removeChild(
                        link
                    );


                    setTimeout(() => {

                        URL.revokeObjectURL(
                            url
                        );

                    }, 1000);

                },

                "image/png"

            );

        }
    );


// ==========================================
// OPEN DESTINATION
// ==========================================

$("openDestination")
    .addEventListener(
        "click",
        () => {

            if (!lastDestination)
                return;


            try {

                const url =
                    new URL(
                        lastDestination
                    );


                if (

                    url.protocol ===
                    "http:" ||

                    url.protocol ===
                    "https:"

                ) {

                    window.open(

                        url.href,

                        "_blank",

                        "noopener,noreferrer"

                    );

                }

                else {

                    alert(
                        "The QR does not contain a normal web URL."
                    );

                }

            }

            catch {

                alert(
                    "The recovered QR contains text/data."
                );

            }

        }
    );