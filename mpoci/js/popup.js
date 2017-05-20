// Validating empty fields
function checkEmpty() {
  if (document.getElementById('notes').value == "") {
    document.alert("Mising Notes!"))
  } else {
    document.getElementById('confirmForm').submit();
  }
}

function divShow() {
  document.getElementById('confirmDiv').style.display = 'block';
}

function divHide() {
  document.getElementById('confirmDiv').style.display = 'none';
}
