<?php
require('{{ CONFIG_FILE }}');

if (empty($CONFIG)){
  throw new Exception('Config is empty');
}

$cnt = count($argv);
$trusted = array('localhost');
for($i=1; $i<$cnt; $i++){
  $trusted[] = trim($argv[$i]);
}

$CONFIG['trusted_domains'] = $trusted;
var_export($CONFIG);

