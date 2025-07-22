package cmd

import (
	"fmt"
	"strings"

	"github.com/accuknox/accuknox-cli-v2/pkg/imagescan"
	kubesheildConfig "github.com/accuknox/kubeshield/pkg/scanner/config"
	"github.com/spf13/cobra"
)

var (
	HOST_NAME                   string
	RUN_TIME                    string
	artifactEndpointPath        string
	cfg                         = kubesheildConfig.Config{}
	defaultArtifactEndpointPath = "/api/v1/artifact/"
)

var imageScanCmd = &cobra.Command{
	Use:   "image-scan",
	Short: "scans vm container images",
	Long: `Scans VM container images 
and sends back the result to saas
		`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		if strings.HasPrefix(cfg.ScanConfig.ArtifactAPI, "http://") {
			return fmt.Errorf("http scheme not supported: %s", cfg.ScanConfig.ArtifactAPI)
		}

		// Adds Scheme if not present
		if !strings.HasPrefix(cfg.ScanConfig.ArtifactAPI, "https://") {
			cfg.ScanConfig.ArtifactAPI = "https://" + cfg.ScanConfig.ArtifactAPI
		}

		// Checks whether the domain is in vaild regex pattern
		if !imagescan.IsValidDomain(cfg.ScanConfig.ArtifactAPI) {
			return fmt.Errorf("invalid domain name: %s", cfg.ScanConfig.ArtifactAPI)
		}

		// if artifact endpoint(after domain) is empty then use default value
		if artifactEndpointPath == "" {
			artifactEndpointPath = defaultArtifactEndpointPath
		}

		if !strings.HasPrefix(artifactEndpointPath, "/") {
			artifactEndpointPath = "/" + artifactEndpointPath
		}

		cfg.ScanConfig.ArtifactAPI += artifactEndpointPath
		return imagescan.DiscoverAndScan(cfg, HOST_NAME, RUN_TIME)
	},
}

func init() {

	// Artifact API Configurations
	imageScanCmd.Flags().StringVarP(&cfg.ScanConfig.ArtifactAPI, "artifactEndpoint", "", "",
		"Specify the domain name of the artifact endpoint")
	imageScanCmd.Flags().StringVarP(&artifactEndpointPath, "artifactEndpointPath", "", "",
		"Optional: specify the URL path segment after the domain name")
	imageScanCmd.Flags().StringVarP(&cfg.ScanConfig.Label, "label", "l", "", "used to filter the finding based on the label")
	imageScanCmd.Flags().StringVarP(&cfg.ScanConfig.ArtifactToken, "token", "t", "", "token required for authentication")
	imageScanCmd.Flags().StringVarP(&cfg.ScanConfig.TenantID, "tenantId", "", "", "tenant id")

	// Scan Configurations
	imageScanCmd.Flags().StringVarP(&HOST_NAME, "hostname", "", "", "name of the host")
	imageScanCmd.Flags().StringVarP(&RUN_TIME, "runtime", "r", "", "container runtime used in the host machine")

	// Required Flags Validation
	imageScanCmd.MarkFlagsOneRequired("artifactEndpoint", "token", "label", "tenantId")
	imageScanCmd.MarkFlagsRequiredTogether("artifactEndpoint", "token", "label", "tenantId")
	rootCmd.AddCommand(imageScanCmd)
}
