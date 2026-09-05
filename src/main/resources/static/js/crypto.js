function validateLanguage() {
  const text = document.getElementById("text").value;
  const language = document.getElementById("language").value;

  const hasEnye = text.includes("Ñ") || text.includes("ñ");

  if (hasEnye && language === "ENGLISH") {
    alert("El texto contiene Ñ. Debes seleccionar Español.");
    return false;
  }

  return true;
}

function updateParameters() {
  const type = document.getElementById("type").value;

  const keyField = document.getElementById("key-field");
  const affineFields = document.getElementById("affine-fields");
  const key = document.getElementById("key");
  const keyHelp = document.getElementById("key-help");

  if (type === "AFFINE") {
    keyField.style.display = "none";
    affineFields.style.display = "grid";
  } else {
    keyField.style.display = "flex";
    affineFields.style.display = "none";

    if (type === "CAESAR") {
      key.placeholder = "Ejemplo: 5";
      keyHelp.textContent = "Para César utiliza un número.";
    }

    if (type === "VIGENERE") {
      key.placeholder = "Ejemplo: CLAVE";
      keyHelp.textContent = "Para Vigenère utiliza una palabra como clave.";
    }
  }
}

document.addEventListener("DOMContentLoaded", updateParameters);
