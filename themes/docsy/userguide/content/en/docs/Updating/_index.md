---
title: "Updating Docsy"
linkTitle: "Updating Docsy"
weight: 8
description: >
 Keeping the theme up to date.
---

We hope to continue to make improvements to the theme [along with the Docsy community](/docs/contribution-guidelines/). 
If you have cloned the example site (or are otherwise using the theme as a submodule), you can update the Docsy theme
yourself. 

Updating Docsy means that your site will build using the latest version of Docsy at `HEAD` and include 
all the new commits or changes that have been merged since the point in time that you initially added the Docsy 
submodule, or last updated. Updating won't affect any modifications that you made in your own project to 
[override the Docsy look and feel](/docs/adding-content/lookandfeel/), as your overrides 
don't modify the theme itself. For details about what has changed in the theme, see the list of 
[Docsy commits](https://github.com/google/docsy/commits/master).

Depending on how you chose to use Docsy, follow the corresponding steps to update the theme:

## Update a Docsy submodule

If you are using the Docsy theme as a submodule in your project (for example, if you've copied our example site), you update the submodule:

1. Navigate to the root of your local project, then run:

        git submodule update --remote

    
1. Add and then commit the change to your project:

        git add themes/
        git commit -m "Updating theme submodule"


1. Push the commit to your project repo. For example, run:

        git push origin master

    
## Update your Docsy clone

If you [cloned the Docsy theme](/docs/getting-started/#cloning-the-docsy-theme-to-your-projects-themes-subdirectory) into
the `themes` folder in your project, then you use the `git pull` command:

1. Navigate to the `themes` directory in your local project:

        cd themes

1. Ensure that `origin` is set to `https://github.com/google/docsy.git`:

        git remote -v

1. Update your local clone:

        git pull origin master

If you have made any local changes to the cloned theme, you must manually resolve any merge conflicts.

