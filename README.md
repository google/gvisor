# gVisor Website

This repository holds the content for the gVisor website. It uses
[hugo](https://gohugo.io/) to generate the website and
[Docsy](https://github.com/google/docsy) as the theme. 

## Requirements

Building the website requires the extended version of
[hugo](https://gohugo.io/) and [node.js](https://nodejs.org/) in order to
generate CSS files. Please install them before building.

- Node.js >= 10.15.0 LTS
- hugo extended >= v0.53

## Building

Build the website using `make`:

```
make
```

This will output the App Engine application code, configuration, and html and
CSS into the `public/` directory.

## Testing

You can use the hugo web server for testing. This will start a webserver that
will rebuild the site when you make content changes:

```
make server
```

Access the site at http://localhost:8080

## Deploy

Deploying the website to App Engine requires gcloud. First create a configuration:

```
{
  gcloud config configurations create gvisor-website
  gcloud config set project gvisor-website
}
```

Deploy the application:

```
make deploy
```

## Editing documentation

Documentation is located in the [content/docs/](content/docs/) directory.
Documentation is written in markdown with hugo extensions. Please read more
about [content management](https://gohugo.io/categories/content-management) in
the hugo documentation.

## Submit a Build

Normally a build is triggered when you push to the gvisor-website repository.
However, you can submit a build to Cloud Build manually.

As one-time setup, enable the App Engine Admin API, and set IAM roles for the [Cloud Build service
account](https://cloud.google.com/cloud-build/docs/securing-builds/set-service-account-permissions).

```
{
  PROJECT_NUMBER=$(gcloud projects list --filter=gvisor-website --format="value(projectNumber)")
  gcloud services enable appengine.googleapis.com
  gcloud projects add-iam-policy-binding gvisor-website \
    --member=serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com \
    --role='roles/appengine.deployer'
  gcloud projects add-iam-policy-binding gvisor-website \
    --member=serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com \
    --role='roles/appengine.serviceAdmin'
}
```

Submit the build.

```
make cloud-build
```
