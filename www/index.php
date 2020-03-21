<?php
$config = file_get_contents("../config.json");
if ($config === false) {header("Location: /?invalid_config");exit();}

$json_config = json_decode($config, true);
if ($json_config === null) {header("Location: /?invalid_config");exit();}
$found=false;
$scanned_ip="";
$valid=false;
$publickey = $json_config["Recaptcha"]["PublicKey"];
if($json_config["VirusTotal"]["Persistence"]=="SQL"){
 $servername = $json_config["VirusTotal"]["PersistenceCredentials"]["host"];
 $username_r = $json_config["VirusTotal"]["PersistenceCredentials"]["username_r"];
 $password_r = $json_config["VirusTotal"]["PersistenceCredentials"]["password_r"];
 $username_rw = $json_config["VirusTotal"]["PersistenceCredentials"]["username_rw"];
 $password_rw = $json_config["VirusTotal"]["PersistenceCredentials"]["password_rw"];
 $username_u = $json_config["VirusTotal"]["PersistenceCredentials"]["username_u"];
 $password_u = $json_config["VirusTotal"]["PersistenceCredentials"]["password_u"];
 $dbname = $json_config["VirusTotal"]["PersistenceCredentials"]["database"];
 if(isset($_POST) && !empty($_POST)){
  $scanned_ip=isset($_POST['ip']) && !empty($_POST['ip'])  && !is_array($_POST['ip']) ? $_POST['ip'] : "";
  if(!$scanned_ip){header("Location: /?invalid_ip");exit();}
  if (filter_var($scanned_ip, FILTER_VALIDATE_IP)) {
  } else {header("Location: /?invalid_ip");exit();}

  $recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify';
  $recaptcha_secret = $json_config["Recaptcha"]["PrivateKey"];
  $recaptcha_response=isset($_POST['recaptcha_response']) && !empty($_POST['recaptcha_response'])  && !is_array($_POST['recaptcha_response']) ? $_POST['recaptcha_response'] : "";

  // Make and decode POST request:
  $recaptcha = file_get_contents($recaptcha_url . '?secret=' . $recaptcha_secret . '&response=' . $recaptcha_response);
  $recaptcha = json_decode($recaptcha);

  // Take action based on the score returned:
  if ($recaptcha->score >= 0.5) {
    // Verified
  } else {
    // Not verified
    header("Location: /?invalid_captcha");exit();
  }

  $valid=true;
  try {
  $options = [
    PDO::ATTR_EMULATE_PREPARES   => false, // turn off emulation mode for "real" prepared statements
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, //turn on errors in the form of exceptions
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, //make the default fetch be an associative array
  ];

  $conn_r = new PDO("mysql:host=$servername;dbname=$dbname", $username_r, $password_r, $options);
  $conn_r->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $conn_rw = new PDO("mysql:host=$servername;dbname=$dbname", $username_rw, $password_rw, $options);
  $conn_rw->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $conn_u = new PDO("mysql:host=$servername;dbname=$dbname", $username_u, $password_u, $options);
  $conn_u->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_ips_table where scanned_ip=:scanned_ip");
  $stmt->bindParam(":scanned_ip", $scanned_ip);
  $stmt->execute();

  // set the resulting array to associative
  $ips=array();
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $ips[] = $row;
  }
  if(count($ips)>0){
    if(time()-$ips[0]["last_scanned_time"]>60){
      $stmt = $conn_u->prepare("UPDATE vt_scanned_ips_table SET last_scanned_time=:last_scanned_time where scanned_ip=:scanned_ip");
      $stmt->bindParam(":scanned_ip", $scanned_ip);
      $time=time();
      $stmt->bindParam(":last_scanned_time", $time);
      $stmt->execute();

      $command = "../VirusTotal.py '$scanned_ip'";
      $output = shell_exec($command);
    }else{
      $found=true;

      $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_resolutions_table where ip_id=:ip_id");
      $stmt->bindParam(":ip_id", $ips[0]["id"]);
      $stmt->execute();
      $resolutions=array();
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $resolutions[] = $row;
      }

      $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_urls_table where ip_id=:ip_id");
      $stmt->bindParam(":ip_id", $ips[0]["id"]);
      $stmt->execute();
      $urls=array();
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $urls[] = $row;
      }

      $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_referring_files_table where ip_id=:ip_id");
      $stmt->bindParam(":ip_id", $ips[0]["id"]);
      $stmt->execute();
      $referring_files=array();
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $referring_files[] = $row;
      }

      $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_downloads_table where ip_id=:ip_id");
      $stmt->bindParam(":ip_id", $ips[0]["id"]);
      $stmt->execute();
      $downloads=array();
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $downloads[] = $row;
      }

      $stmt = $conn_r->prepare("SELECT * FROM vt_scanned_communicating_files_table where ip_id=:ip_id");
      $stmt->bindParam(":ip_id", $ips[0]["id"]);
      $stmt->execute();
      $communicating_files=array();
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $communicating_files[] = $row;
      }
    }
  }else{
    // prepare and bind
    $stmt = $conn_rw->prepare("INSERT INTO vt_scanned_ips_table (scanned_ip, last_scanned_time) VALUES (:scanned_ip, :last_scanned_time)");
    $stmt->bindParam(":scanned_ip", $scanned_ip);
    $time=time();
    $stmt->bindParam(":last_scanned_time", $time);
    $stmt->execute();

    $command = "../VirusTotal.py '$scanned_ip'";
    $output = shell_exec($command);
  }
  //$conn_r->close();
  //$conn_rw->close();

  }catch(PDOException $e)
  {
    echo "Error occured"; //"Error: " . $e->getMessage();
  }
 }
}
?>
<html>
<header>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>

<style>td{white-space:nowrap;}.h3{display:inline;}</style>
<!------ Include the above in your HEAD tag ---------->

<link href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet">
<script>
function ValidateIPaddress(ipaddress)
{
 if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(scan.ip.value))
  {
    return (true)
  }
alert("You have entered an invalid IP address!")
return (false)
}

</script>
</header>
<body onload='document.scan.ip.focus()'>
   <div class="container">
      <div class="col-md-6 mx-auto text-center">
         <div class="header-title">
            <h1 class="wv-heading--title text-info">
               Empire Total
            </h1>
            <h5 class="text-info">Based on Virus Total API</h5>
         </div>
      </div>
      <div class="row">
         <div class="col-md-12 mx-auto">
            <div class="myform form">
               <form action="" method="post" name="scan">
                  <div class="form-group">
                     <input type="text" name="ip"  class="form-control my-input" id="ip" placeholder="IP Address" autocomplete="false">
                  </div>
                  <div class="text-center ">
                     <button type="submit" class=" btn btn-block btn-info send-button tx-tfm" onclick="ValidateIPaddress(document.scan.ip)">Scan the IP address</button>
                  </div>
                  <p class="small mt-3">This platform is a gateway between the user and the <a href="https://www.virustotal.com/gui/home/search">Virus Total</a> API. It manages the API key usage since there is <a href="https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-">a limit when using the public API key</a>. When an IP address is scanned, it's stored in our database so when the same IP address is scanned again in a short period of time (<1 minute), the platform will show the cached results. Otherwise, the platform will show directly the scan result using the Virus Total API. This platform is developed using advanced security technics to secure the web page form.</p>

<input type="hidden" id="recaptchaResponse" name="recaptcha_response">
<script src="https://www.google.com/recaptcha/api.js?render=<?php echo $publickey;?>"></script>
<script>
grecaptcha.ready(function() {
    grecaptcha.execute('<?php echo $publickey;?>', {action: 'homepage'}).then(function(token) {
      var recaptchaResponse = document.getElementById('recaptchaResponse');
      recaptchaResponse.value = token;
    });
});
</script>

               </form>
            </div>
         </div>
      </div>
   </div>
   <?php if($valid){?>
   <?php if(!$found){?>
   <iframe src="output/<?php echo $scanned_ip;?>-VirusTotal.html" frameborder="0" allowfullscreen
    style="width:100%;height:100%;"></iframe>
   <?php }else{?>
<h3>IP Address: <?php echo $scanned_ip;?></h3>
<h4>Passive DNS</h4>
<h5>(<?php echo count($resolutions);?> found)</h5>
<table class="table table-sm">
  <thead><tr><th>Date resolved</th><th>Domain</th></tr></thead>
  <tbody>
    <?php foreach($resolutions as $resolution){?>
    <tr>
      <td><?php echo $resolution["scanned_time"];?></td>
      <td><?php echo $resolution["domain"];?></td>
    </tr>
    <?php }?>
  </tbody>
</table>
<?php if(count($urls)>0){?>
<h4>URLs</h4>
<h5>(<?php echo count($urls);?> found)</h5>
<table class="table table-sm">
  <thead><tr><th>Scanned</th><th>Detections</th><th>URL</th></tr></thead>
  <tbody>
    <?php foreach($urls as $url){?>
    <tr>
      <td><?php echo $url["scanned_time"];?></td>
      <td><?php echo $url["detections"];?></td>
      <td><?php echo $url["url"];?></td>
    </tr>
    <?php }?>
  </tbody>
</table>
<?php }?>
<?php if(count($downloads)>0){?>
<h4>Downloaded Files</h4>
<h5>(<?php echo count($downloads);?> found)</h5>
<table class="table table-sm">
  <thead><tr><th>Scanned</th><th>Detections</th><th>File Hash (sha256)</th></tr></thead>
  <tbody>
    <?php foreach($downloads as $download){?>
    <tr>
      <td><?php echo $download["scanned_time"];?></td>
      <td><?php echo $download["detections"];?></td>
      <td><?php echo $download["hash"];?></td>
    </tr>
    <?php }?>
  </tbody>
</table>
<?php }?>
<?php if(count($communicating_files)>0){?>
<h4>Communicating Files</h4>
<h5>(<?php echo count($communicating_files);?> found)</h5>
<table class="table table-sm">
  <thead><tr><th>Scanned</th><th>Detections</th><th>File Hash (sha256)</th></tr></thead>
  <tbody>
    <?php foreach($communicating_files as $communicating_file){?>
    <tr>
      <td><?php echo $communicating_file["scanned_time"];?></td>
      <td><?php echo $communicating_file["detections"];?></td>
      <td><?php echo $communicating_file["hash"];?></td>
    </tr>
    <?php }?>
  </tbody>
</table>
<?php }?>
<?php if(count($referring_files)>0){?>
<h4>Files Referring</h4>
<h5>(<?php echo count($referring_files);?> found)</h5>
<table class="table table-sm">
  <thead><tr><th>Scanned</th><th>Detections</th><th>File Hash (sha256)</th></tr></thead>
  <tbody>
    <?php foreach($referring_files as $referring_file){?>
    <tr>
      <td><?php echo $referring_file["scanned_time"];?></td>
      <td><?php echo $referring_file["detections"];?></td>
      <td><?php echo $referring_file["hash"];?></td>
    </tr>
    <?php }?>
  </tbody>
</table>
<?php }?>
   <?php }?>
   <?php }?>
</body>
</html>
<?php
?>
