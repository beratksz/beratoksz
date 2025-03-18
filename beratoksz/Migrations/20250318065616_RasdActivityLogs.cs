using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace beratoksz.Migrations
{
    /// <inheritdoc />
    public partial class RasdActivityLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "City",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Country",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "City",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "Country",
                table: "ActivityLogs");
        }
    }
}
