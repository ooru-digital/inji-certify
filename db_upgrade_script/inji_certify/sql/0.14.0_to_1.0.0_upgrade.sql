UPDATE certify.credential_config
SET display = COALESCE((
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' IS NOT NULL
                           AND (elem->'logo')::jsonb ? 'url' THEN
                           jsonb_set(
                                   elem::jsonb,
                                   '{logo}',
                                   ((elem->'logo')::jsonb - 'url')
                    || jsonb_build_object('uri', (elem->'logo')::jsonb -> 'url')
                )
                       ELSE elem::jsonb
                       END
           )
    FROM jsonb_array_elements(display::jsonb) AS elem
), '[]'::jsonb)
WHERE display IS NOT NULL;

ALTER TABLE certify.credential_config
RENAME COLUMN credential_subject TO claims;
COMMENT ON COLUMN certify.credential_config.claims IS 'Claims: JSON object containing subject attributes schema.';

UPDATE certify.credential_config
SET credential_format = 'dc+sd-jwt'
WHERE credential_format = 'vc+sd-jwt';

UPDATE certify.credential_config
SET proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb
WHERE proof_types_supported = '{}'::jsonb;

-- Replace legacy Ed25519 with EdDSA in existing JWT proof algorithm lists
UPDATE certify.credential_config
SET proof_types_supported = jsonb_set(
    proof_types_supported,
    '{jwt,proof_signing_alg_values_supported}',
    (
      SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
      FROM (
        SELECT
          CASE
            WHEN alg = '"Ed25519"'::jsonb THEN '"EdDSA"'::jsonb
            ELSE alg
          END AS val
        FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
      ) sub
    )
)
WHERE proof_types_supported #> '{jwt,proof_signing_alg_values_supported}' IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
      WHERE alg = '"Ed25519"'::jsonb
  );