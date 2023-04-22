# Manually Deploying mpc-recovery to GCP

GCP Project ID: pagoda-discovery-platform-dev
Service account: mpc-recovery@pagoda-discovery-platform-dev.iam.gserviceaccount.com

First, if you don't have credentials, go to [here](https://console.cloud.google.com/iam-admin/serviceaccounts/details/106859519072057593233;edit=true/keys?project=pagoda-discovery-platform-dev) and generate a new one for yourself.

Now, assuming you saved it as `mpc-recovery-creds.json` in the current working directory:

```bash
$ cat pagoda-discovery-platform-dev-92b300563d36.json | docker login -u _json_key --password-stdin https://us-east1-docker.pkg.dev
```

This will log you into the GCP Artifact Repository.

Build the mpc-recovery docker image like you usually would, but tag it with this image name:

```bash
$ docker build . -t us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/mpc-recovery-tmp/mpc-recovery
```

Push the image to GCP Artifact Registry:

```bash
$ docker push us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/mpc-recovery-tmp/mpc-recovery
```

 You can check that the image has been successfully uploaded [here](https://console.cloud.google.com/artifacts/docker/pagoda-discovery-platform-dev/us-east1/mpc-recovery-tmp?project=pagoda-discovery-platform-dev).

 Now reset the VM instance:
 
 ```bash
 $ gcloud compute instances reset mpc-recovery-tmp-0
 ```

 The API should be available shortly on `http://34.139.85.130:3000`.
