
document.addEventListener("DOMContentLoaded", function () {

    const button = document.getElementById("statusButton");
    const message = document.getElementById("statusMessage");

    button.addEventListener("click", function () {

        message.textContent =
            "Dashboard interface is responding successfully.";

    });

});
