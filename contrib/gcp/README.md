Portier Deployment to Google Cloud Platform (GCP).

The deployment fronts Portier with Redis running under [Cloud Run](https://cloud.google.com/run) with an [external cross-region global load balancer](https://cloud.google.com/load-balancing/docs/https#cross-region_load_balancing) providing [resilience to region failure](https://cloud.google.com/run/docs/multiple-regions).

Costs are ~$50/region/month plus ~$20/month when idle:

 * [Cloud Run](https://cloud.google.com/run/pricing#tables) (~$10/region/month)
     * You may wish to pick a Tier 1 region for better pricing where possible
 * [Redis](https://cloud.google.com/memorystore/docs/redis/pricing#instance_pricing) (~$40/region/month)
     * Uses basic tier with 1GiB capacity
 * [Load Balancer](https://cloud.google.com/vpc/network-pricing#lb) (~$20/month)
     * Deployment fits within the first five forwarding rules pricing

It is recommended, though not necessary, that you deploy to two regions for the purpose of resilience. Further adding more regions is unlikely to provide any measurable benefits as low latency is not a requirement of a service such as Portier.

## Related Links

 * [Deployment Manager](https://cloud.google.com/deployment-manager)
 * [Jinja Template Documentation](https://jinja.palletsprojects.com/en/2.11.x/templates/)

## Outstanding Issues

 * The [type providers](https://cloud.google.com/deployment-manager/docs/configuration/type-providers/advanced-configuration-options) used need massaging to allow updates
 * Hard coding of the Redis port to `6379/tcp`
     * workaround: `Reference [$(ref.portier-europe-west4-redis.port)], was not of type string but [NUMBER], cannot replace inside ["redis://:abcd@192.0.2.1:$($(ref.portier-europe-west4-redis.port))/0\n"]`
     * GCP's Deployment Manager is mostly awful, so when GCP throws you lemons, it provides zero tools (or documentation) to make lemonade
         * there is no cast operator available that works on `$(ref ...)`
         * we cannot use [`outputs`](https://cloud.google.com/deployment-manager/docs/configuration/expose-information-outputs) as it uses pass by reference and creates the same problem
 * support for [in-transit encryption](https://cloud.google.com/memorystore/docs/redis/in-transit-encryption)
     * [redis crate supports it](https://docs.rs/redis/0.20.0/redis/enum.ConnectionAddr.html#variant.TcpTls) though Portier's [`pubsub.rs`](../../src/utils/redis/pubsub.rs) explicitly does not
         * we would need to be able to set a [custom private CA](https://cloud.google.com/memorystore/docs/redis/in-transit-encryption#certificate_authority) for these connections
         * could use an SSL sidecar such as [`socat`](http://www.dest-unreach.org/socat/)/[`stunnel`](https://www.stunnel.org/) (and no `LD_PRELOAD` hack for SSL clients exist) but container users tend to subscribe to various purity laws that frown upon running supervisors whilst ignoring the very real world problems it solves
     * not a huge problem as the expected deployment is that this will be the sole service running in a GCP project so nothing would be around to sniff the wire traffic even if it could
 * `smtp_password` and the Redis connection URL are not stored in [Google Key Manager Service](https://cloud.google.com/kms)
     * Portier emits the Redis authentication string as a logging message captured in [Logs Explorer](https://console.cloud.google.com/logs/query) anyway...

# Preflight

You will need to already have have a GCP account, created a project with an billing account assigned to it and that you have at least 'Editor' permissions on it.

    gcloud --project [PROJECT_ID] services enable \
        cloudbuild.googleapis.com \
        containerregistry.googleapis.com \
        deploymentmanager.googleapis.com \
        redis.googleapis.com \
        run.googleapis.com \
        sourcerepo.googleapis.com \
        vpcaccess.googleapis.com

Where `[PROJECT_ID]` is the GCP project name you want to deploy to.

Obtain the `[PROJECT_NUMBER]` which is the `projectNumber` output from running:

    gcloud projects describe [PROJECT_ID]

Now elevate the permissions of the deployment manager account using:

    gcloud projects add-iam-policy-binding [PROJECT_ID] --member serviceAccount:[PROJECT_NUMBER]@cloudservices.gserviceaccount.com --role roles/source.admin
    gcloud projects add-iam-policy-binding [PROJECT_ID] --member serviceAccount:[PROJECT_NUMBER]@cloudservices.gserviceaccount.com --role roles/run.admin

Create a GCP Deployment Manager configuration file to describe the deployment:

    cp contrib/gcp/portier.yaml.dist contrib/gcp/portier.yaml

Edit `contrib/gcp/portier.yaml` to reflect the desired deployment as detailed in [`portier.jinja.schema`](./portier.jinja.schema); most of which just populates the variables described in [`config.toml`](../../config.toml.dist).

**N.B.** once deployed you must not change the *ordering* of `regions` as it is used to select IP ranges that once set are immutable, if you need to disable a region update the entry to include the string 'ignore' which is case insensitively matched on by the deployment template

Preview the deployment by running:

    gcloud --project [PROJECT_ID] deployment-manager deployments create [DEPLOYMENT] --config contrib/gcp/portier.yaml --preview

Where `[DEPLOYMENT]` is what you want to name the deployment (recommended you use `portier`).

If you are happy with the proposed deployment, then run:

    gcloud --project [PROJECT_ID] deployment-manager deployments cancel-preview [DEPLOYMENT]
    gcloud --project [PROJECT_ID] deployment-manager deployments update [DEPLOYMENT] --config contrib/gcp/portier.yaml
    git config credential.'https://source.developers.google.com'.helper gcloud.sh
    git remote add google https://source.developers.google.com/p/[PROJECT_ID]/r/[DEPLOYMENT]
    git push --force --all google
    git push --force --tags google

# Deploy

To update the deployment, run:

    gcloud --project [PROJECT_ID] deployment-manager deployments update [DEPLOYMENT] --config contrib/gcp/portier.yaml

## Remove

    gcloud --project [PROJECT_ID] deployment-manager deployments delete [DEPLOYMENT]

### Abandon

This process descibes how to remove the deployment whilst retaining the IPs and certificate resources, ready for you to be able to redeploy without error.

    gcloud --project [PROJECT_ID] deployment-manager deployments delete [DEPLOYMENT] --delete-policy=abandon
    gcloud --project [PROJECT_ID] compute forwarding-rules delete [DEPLOYMENT]-globalforwardingrule-ipv4 --global
    gcloud --project [PROJECT_ID] compute forwarding-rules delete [DEPLOYMENT]-globalforwardingrule-ipv6 --global
    gcloud --project [PROJECT_ID] compute target-https-proxies delete [DEPLOYMENT]-targethttpsproxy
    gcloud --project [PROJECT_ID] compute url-maps delete [DEPLOYMENT]-urlmap
    gcloud --project [PROJECT_ID] compute backend-services delete [DEPLOYMENT]-backendservice --global
    gcloud --project [PROJECT_ID] compute network-endpoint-groups delete [DEPLOYMENT] --region europe-west4
    gcloud --project [PROJECT_ID] run services delete --platform managed [DEPLOYMENT] --region europe-west4
    gcloud --project [PROJECT_ID] compute networks vpc-access connectors delete [DEPLOYMENT] --region europe-west4
    #gcloud --project [PROJECT_ID] redis instances delete [DEPLOYMENT] --region europe-west4
    #gcloud --project [PROJECT_ID] beta builds triggers delete [DEPLOYMENT]
    #gcloud --project [PROJECT_ID] source repos delete [DEPLOYMENT]

**N.B.** you do not need to delete Redis, the trigger or source repo, but the commands are shown for completeness

# Deploy

If you want to deploy a new version of Portier, just update your local repo and run:

    git tag --force prod
    git push --force --all google
    git push --force --tags google

This will kick off a new [build you can monitor](https://console.cloud.google.com/cloud-build/dashboard) using:

    gcloud --project [PROJECT_ID] builds list

After about twenty minutes you should have a new image built ready for use.

...WIP get live by creating and making live a new revision in Cloud Run

## Data Directory

If you are just looking to update the data directory, then kick of a new build manually with:

    gcloud --project [PROJECT_ID] beta builds triggers run portier --tag=prod

# Development

...WiP

    docker build -t portier/broker:latest --build-arg data=url --build-arg data_url=http://localhost:8080/bob.tar.gz .

Manually trigger build if you have only updated the data_url via https://console.cloud.google.com/cloud-build/triggers

Edit the [Cloud Run `[DEPLOYMENT]` Service](https://console.cloud.google.com/run) directory to amend runtime environment settings such as `BROKER_ALLOWED_ORIGINS`.
